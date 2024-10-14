package v4

import (
	"dhcp/dhcp/frame"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	selecting = iota
	initReboot
	renewing
	rebinding
)

type binding struct {
	IP         net.IP
	MAC        net.HardwareAddr
	Expiration time.Time
}

type DHCPv4 struct {
	mu        sync.Mutex
	ipPool    *ipPool
	bindings  map[uint64]*binding
	allocated map[uint64]bool
	config    *Config

	udpConn net.PacketConn
	rawConn net.PacketConn

	clientPort int
	serverPort int
}

func (s *DHCPv4) Start() {
	go s.startReadConn()
	go s.cleanupExpiredLeases()
}

func MakeDHCPv4(c *Config) (*DHCPv4, error) {
	pool, err := newIPPool(c.Start, c.End)
	if err != nil {
		return nil, err
	}
	return &DHCPv4{
		ipPool:     pool,
		bindings:   make(map[uint64]*binding),
		allocated:  make(map[uint64]bool),
		config:     c,
		clientPort: 68,
		serverPort: 67,
	}, nil
}

func (s *DHCPv4) startReadConn() {
	for {
		buf := make([]byte, 1500)
		n, addr, err := s.udpConn.ReadFrom(buf)
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
		go s.handlePacket(buf[:n], upeer)
	}

}

func (s *DHCPv4) handlePacket(p []byte, addr *net.UDPAddr) {
	packet, err := Decode(p)
	if err != nil {
		slog.Error("Error decoding packet", "error", err)
		return
	}
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

func (s *DHCPv4) handleDiscover(packet *Packet, addr *net.UDPAddr) {
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

func (s *DHCPv4) createOffer(packet *Packet) *Packet {
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

func (s *DHCPv4) handleRelease(packet *Packet) {
	s.releaseIP(packet.CIAddr)
}

func (s *DHCPv4) handleDecline(packet *Packet) {
	s.releaseIP(packet.CIAddr)
}

func (s *DHCPv4) releaseIP(ip net.IP) {
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

func (s *DHCPv4) setupListener() (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 67})
	if err != nil {
		return nil, err
	}
	slog.Info("Listening on", "addr", conn.LocalAddr())
	return conn, nil
}

func (s *DHCPv4) cleanupExpiredLeases() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

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
	}
}

func (s *DHCPv4) createReplyOptions() *ReplyOptions {
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

func (s *DHCPv4) handleRequest(packet *Packet, addr *net.UDPAddr) {
	state := s.determineClientState(packet)
	var response *Packet
	switch state {
	case selecting:
		s.mu.Lock()
		defer s.mu.Unlock()

		requestedIP := packet.GetOption(OptionRequestedIPAddress)
		serverIdentifier := packet.GetOption(OptionServerIdentifier)

		if !net.IP(serverIdentifier).Equal(s.config.ServerIP) {
			// Client has selected a different server
			return
		}
		response = s.buildResponseToBinding(packet, requestedIP)

	case initReboot:
		s.mu.Lock()
		defer s.mu.Unlock()
		requestedIP := packet.GetOption(OptionRequestedIPAddress)
		response = s.buildResponseToBinding(packet, requestedIP)

	case renewing, rebinding:
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

func (s *DHCPv4) buildResponseToBinding(packet *Packet, ip net.IP) (response *Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *DHCPv4) determineClientState(packet *Packet) int {
	emptyServer := packet.SIAddr == nil || packet.SIAddr.Equal(net.IPv4zero)
	hasRequestedIP := packet.GetOption(OptionRequestedIPAddress) != nil && !net.IPv4zero.Equal(packet.GetOption(OptionServerIdentifier))
	clientIPIsZero := packet.CIAddr.Equal(net.IPv4zero)

	if !emptyServer && hasRequestedIP && clientIPIsZero {
		return selecting
	}

	if emptyServer && hasRequestedIP && clientIPIsZero {
		return initReboot
	}

	if emptyServer && !clientIPIsZero {
		if packet.IsBroadcast() {
			return rebinding
		}
		return renewing
	}
	return -1
}

func (s *DHCPv4) sendPacket(p *Packet, sendAddr *net.UDPAddr) error {

	isNak := p.GetOption(OptionDHCPMessageType)[0] == DHCPNAK

	if notEmpty(p.GIAddr) {
		if isNak {
			p.SetBroadcast()
		} else {
			// return to relay agent
			sendAddr = &net.UDPAddr{IP: p.GIAddr, Port: s.serverPort}
		}
	} else if isNak {
		// always broadcast NAK
		sendAddr = &net.UDPAddr{IP: net.IPv4bcast, Port: s.clientPort}
	} else if notEmpty(p.CIAddr) {
		// send directly to client ip
		sendAddr = &net.UDPAddr{IP: p.CIAddr, Port: s.clientPort}
	} else if !p.IsBroadcast() && p.CHAddr != nil {
		// unicast by mac
		e := frame.Ethernet{
			SourcePort:      uint16(s.serverPort),
			DestinationPort: uint16(s.clientPort),
			SourceIP:        s.config.ServerIP,
			DestinationMAC:  p.CHAddr,
			Payload:         p.Encode(),
		}

		_, err := s.rawConn.WriteTo(e.Encode(), nil)
		return err
	} else {
		sendAddr.IP = net.IPv4bcast
	}

	encodedPacket := p.Encode()
	_, err := s.udpConn.WriteTo(encodedPacket, sendAddr)
	if err != nil {
		slog.Error("Failed to send DHCP packet", "error", err, "client", p.CHAddr, "offer_ip", p.CIAddr)
	} else {
		slog.Info("Sent DHCP packet", "client", p.CHAddr, "offer_ip", p.CIAddr)
	}
	return err
}

func (s *DHCPv4) Close() {
	s.udpConn.Close()
	s.rawConn.Close()
}
