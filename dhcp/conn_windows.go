//go:build windows

package dhcp

import (
	"log/slog"
	"net"
	"syscall"
	"time"
)

type winConn struct {
	conn    net.PacketConn
	rawConn syscall.Handle
}

func (c *winConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if v, ok := addr.(*net.UDPAddr); ok {
		return c.conn.WriteTo(p, v)
	}
	//it's ethAddr here, cut udp,ip,eth headers
	return c.conn.WriteTo(p[42:], &net.UDPAddr{IP: net.IPv4bcast, Port: 68})

	// windows doesn't allow to operate on raw sockets
	// there is a library on C that allow to do that, and it's implemented in gopackets library,
	// but the goal is to not use any third-party libraries
}

// this is a dark area
//func sendRawPacket(interfaceName string, dstMac, srcMac [6]byte, ethType uint16, payload []byte) error {
//	dev := C.CString(interfaceName)
//	defer C.free(unsafe.Pointer(dev))
//
//	errBuf := (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
//	defer C.free(unsafe.Pointer(errBuf))
//
//	handle := C.pcap_open_live(dev, 65536, 1, 1000, errBuf)
//	if handle == nil {
//		return fmt.Errorf("failed to open device: %s", C.GoString(errBuf))
//	}
//	defer C.pcap_close(handle)
//
//	frame := make([]byte, 14+len(payload))
//	copy(frame[0:6], dstMac[:])        // Destination MAC
//	copy(frame[6:12], srcMac[:])       // Source MAC
//	frame[12] = byte(ethType >> 8)     // EtherType (high byte)
//	frame[13] = byte(ethType & 0x00FF) // EtherType (low byte)
//	copy(frame[14:], payload)          // Payload
//
//	res := C.pcap_sendpacket(handle, (*C.u_char)(unsafe.Pointer(&frame[0])), C.int(len(frame)))
//	if res != 0 {
//		return fmt.Errorf("pcap_sendpacket failed: %s", C.GoString(C.pcap_geterr(handle)))
//	}
//
//	log.Println("Packet sent successfully!")
//	return nil
//}

func (c *winConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *winConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return c.conn.ReadFrom(p)
}

func (c *winConn) Close() {
	//err1 := c.rawConn.Close()
	err2 := c.conn.Close()
	if err2 != nil {
		slog.Error("Failed to close connection", "err2", err2)
	}
}

func (s *Server) Write(e *Ethernet) error {
	_, err := s.conn.WriteTo(e.udp(), &net.UDPAddr{IP: e.DestinationIP, Port: 68})
	return err
}

func (s *Server) buildConn() (*winConn, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 67})
	if err != nil {
		return nil, err
	}
	slog.Info("Listening on", "addr", udpConn.LocalAddr())
	slog.Info("Broadcasting on", "addr", udpConn.RemoteAddr())

	return &winConn{
		conn: udpConn,
	}, nil
}
