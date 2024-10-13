package dhcp

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	SELECTING = iota
	INIT_REBOOT
	RENEWING
	REBINDING
)

type Connection interface {
	WriteTo(p []byte, addr net.Addr) (n int, err error)

	SetReadDeadline(t time.Time) error
	ReadFrom(p []byte) (n int, addr net.Addr, err error)
	Close()
}

type Server struct {
	mu          sync.RWMutex
	bindings    map[uint64]*binding
	allocated   map[uint64]bool
	ipPool      *IPPool
	config      *Config
	conn        Connection
	wg          sync.WaitGroup
	processChan chan *input
	exitChan    chan struct{}
	mtu         int
}

type input struct {
	data []byte
	addr *net.UDPAddr
}

type Config struct {
	Start         net.IP
	End           net.IP
	Subnet        net.IPNet
	Lease         time.Duration
	RenewalTime   time.Duration
	RebindingTime time.Duration
	DNS           []net.IP
	Router        net.IP
	ServerIP      net.IP
	DomainName    string
}

func (c *Config) validate() error {
	//todo

	return nil
}

type binding struct {
	IP         net.IP
	MAC        net.HardwareAddr
	Expiration time.Time
}

type Offer struct {
	ClientMAC net.HardwareAddr
	OfferIP   net.IP
	ServerIP  net.IP
}

func NewServer(cfg *Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ipPool, err := NewIPPool(cfg.Start, cfg.End)
	if err != nil {
		return nil, err
	}
	s := &Server{
		bindings:    make(map[uint64]*binding),
		allocated:   make(map[uint64]bool),
		ipPool:      ipPool,
		config:      cfg,
		processChan: make(chan *input, 100),
		exitChan:    make(chan struct{}),
	}
	s.mtu, err = getMTU()
	if err != nil {
		slog.Error("Error getting MTU", "error", err)
		//fallback to default
		s.mtu = 1500
	}

	conn, err := s.buildConn()
	if err != nil {
		return nil, err
	}
	s.conn = conn
	return s, nil
}

func (s *Server) Run() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	runAsync(&s.wg, s.run)

	select {
	case <-sig:
		slog.Info("Received signal, stopping server")
		s.exitChan <- struct{}{}
		s.exitChan <- struct{}{}
		close(s.exitChan)
		close(s.processChan)
	}
	slog.Info("waiting for all goroutines to finish")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("All goroutines completed")
	case <-ctx.Done():
		slog.Error("Timed out waiting for goroutines to complete")
	}

	slog.Info("Server stopped")
}

func (s *Server) run() {
	runAsync(&s.wg, s.processPackets)
	runAsync(&s.wg, s.cleanupExpiredLeases)
	runAsync(&s.wg, s.startReadConn)
}

func runAsync(wg *sync.WaitGroup, f func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		f()
	}()
}

func (s *Server) startReadConn() {
	for {
		select {
		case <-s.exitChan:
			slog.Info("Stopping read loop")
			return
		default:
			// Set a read deadline to avoid blocking forever
			err := s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if err != nil {
				slog.Error("Error setting read deadline", "error", err)
			}

			buf := make([]byte, s.mtu)
			n, addr, err := s.conn.ReadFrom(buf)
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					continue
				}
				slog.Error("Error reading packet", "error", err)
				continue
			}
			upeer, ok := addr.(*net.UDPAddr)
			if !ok {
				slog.Error("Invalid UDP address", "addr", addr)
				continue
			}
			s.processChan <- &input{data: buf[:n], addr: upeer}
		}
	}
}

func (s *Server) processPackets() {
	for i := range s.processChan {
		packet, err := Decode(i.data)
		if err != nil {
			slog.Error("Error decoding packet", "error", err)
			continue
		}
		runAsync(&s.wg, func() {
			slog.Info("Processing packet", "packet", packet, "addr", i.addr)
			s.handlePacket(packet, i.addr)
		})
	}
}

func (s *Server) handlePacket(packet *Packet, addr *net.UDPAddr) {
	slog.Info("Received packet", "packet", packet, "addr", addr)
	switch packet.DHCPMessageType() {
	case DHCPDISCOVER:
		s.handleDiscover(packet, addr)
	case DHCPREQUEST:
		s.handleRequest(packet, addr)
	case DHCPRELEASE:
		s.handleRelease(packet)
	case DHCPDECLINE:
		s.handleDecline(packet)
	}
}

func (s *Server) handleDiscover(packet *Packet, addr *net.UDPAddr) {
	offer := s.createOffer(packet)
	if offer == nil {
		slog.Debug("No IP available for offer")
		return
	}
	err := s.sendPacket(offer, addr)
	if err != nil {
		slog.Error("Error sending offer", "error", err)
	}
}

func (s *Server) createOffer(packet *Packet) *Packet {
	s.mu.Lock()
	defer s.mu.Unlock()

	ip := s.ipPool.allocate()
	if ip == nil {
		return nil
	}
	slog.Info("Allocated IP", "ip", ip)
	offer := packet.ToOffer(ip, s.createReplyOptions())
	s.bindings[convertMACToUint64(packet.CHAddr)] = &binding{
		IP:         ip,
		MAC:        packet.CHAddr,
		Expiration: time.Now().Add(s.config.Lease),
	}
	s.allocated[convertIPToUint64(ip)] = true
	slog.Info("Offering IP", "app", ip, "addr", packet.CHAddr.String())
	return offer
}

func (s *Server) handleRelease(packet *Packet) {
	s.releaseIP(packet.CIAddr)
}

func (s *Server) handleDecline(packet *Packet) {
	s.releaseIP(packet.CIAddr)
}

func (s *Server) releaseIP(ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipUint := convertIPToUint64(ip)
	if _, exists := s.allocated[ipUint]; exists {
		delete(s.allocated, ipUint)
		s.ipPool.release(ip)
	}

	for mac, b := range s.bindings {
		if b.IP.Equal(ip) {
			delete(s.bindings, mac)
			break
		}
	}
}

func (s *Server) setupListener() (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 67})
	if err != nil {
		return nil, err
	}
	slog.Info("Listening on", "addr", conn.LocalAddr())
	return conn, nil
}

func (s *Server) cleanupExpiredLeases() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for mac, b := range s.bindings {
				if b.Expiration.Before(now) {
					s.releaseIP(b.IP)
					delete(s.bindings, mac)
				}
			}
			s.mu.Unlock()
		case <-s.exitChan:
			slog.Info("Stopping lease cleanup")
			return
		}
	}
}

type ReplyOptions struct {
	LeaseTime     time.Duration
	RenewalTime   time.Duration
	RebindingTime time.Duration
	SubnetMask    net.IPMask
	Router        net.IP
	DNS           []net.IP
	ServerIP      net.IP
	DomainName    string
}

func (s *Server) createReplyOptions() *ReplyOptions {
	//todo can cache it until config change
	return &ReplyOptions{
		LeaseTime:     s.config.Lease,
		RenewalTime:   s.config.RenewalTime,
		RebindingTime: s.config.RebindingTime,
		SubnetMask:    s.config.Subnet.Mask,
		Router:        s.config.Router,
		DNS:           s.config.DNS,
		ServerIP:      s.config.ServerIP,
		DomainName:    s.config.DomainName,
	}
}

func (s *Server) createAckOrNak(packet *Packet) *Packet {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, exists := s.bindings[convertMACToUint64(packet.CHAddr)]
	if !exists || !b.IP.Equal(packet.CIAddr) {
		slog.Error("Invalid request", "packet", packet)
		return packet.ToNak(s.createReplyOptions())
	}

	b.Expiration = time.Now().Add(s.config.Lease)
	slog.Info("Acknowledging IP", "ip", b.IP)
	return packet.ToAck(b.IP, s.createReplyOptions())
}

func (s *Server) handleRequest(packet *Packet, addr *net.UDPAddr) {
	state := s.determineClientState(packet)
	var response *Packet
	switch state {
	case SELECTING:
		s.mu.Lock()
		defer s.mu.Unlock()

		requestedIP := packet.GetOption(OptionRequestedIPAddress)
		serverIdentifier := packet.GetOption(OptionServerIdentifier)

		if !net.IP(serverIdentifier).Equal(s.config.ServerIP) {
			// Client has selected a different server
			return
		}
		response = s.buildResponseToBinding(packet, requestedIP)

	case INIT_REBOOT:
		s.mu.Lock()
		defer s.mu.Unlock()
		requestedIP := packet.GetOption(OptionRequestedIPAddress)
		response = s.buildResponseToBinding(packet, requestedIP)

	case RENEWING, REBINDING:
		s.mu.Lock()
		defer s.mu.Unlock()
		response = s.buildResponseToBinding(packet, packet.CIAddr)

	default:
		slog.Error("Invalid DHCPREQUEST state")
		return
	}
	if response == nil {
		slog.Error("Error creating response")
		return
	}
	err := s.sendPacket(response, addr)
	if err != nil {
		slog.Error("Error sending response", "error", err)
	}
}

func (s *Server) buildResponseToBinding(packet *Packet, ip net.IP) (response *Packet) {
	b, exists := s.bindings[convertMACToUint64(packet.CHAddr)]
	if !exists || !b.IP.Equal(ip) {
		response = packet.ToNak(s.createReplyOptions())
	} else if b.Expiration.Before(time.Now()) {
		response = packet.ToNak(s.createReplyOptions())
	} else {
		b.Expiration = time.Now().Add(s.config.Lease)
		response = packet.ToAck(b.IP, s.createReplyOptions())
	}
	return response
}

func (s *Server) determineClientState(packet *Packet) int {
	emptyServer := packet.SIAddr == nil || packet.SIAddr.Equal(net.IPv4zero)
	hasRequestedIP := packet.GetOption(OptionRequestedIPAddress) != nil && !net.IPv4zero.Equal(packet.GetOption(OptionServerIdentifier))
	clientIPIsZero := packet.CIAddr.Equal(net.IPv4zero)

	if !emptyServer && hasRequestedIP && clientIPIsZero {
		return SELECTING
	}

	if emptyServer && hasRequestedIP && clientIPIsZero {
		return INIT_REBOOT
	}

	if emptyServer && !clientIPIsZero {
		if packet.IsBroadcast() {
			return REBINDING
		}
		return RENEWING
	}
	return -1
}
