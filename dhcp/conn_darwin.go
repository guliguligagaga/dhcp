//go:build arm64 && darwin

package dhcp

import (
	"log/slog"
	"net"
)

func (s *Server) Write(e *Ethernet, addr net.Addr) error {
	_, err := s.conn.WriteTo(e.Encode(), addr)
	return err
}

func (s *Server) buildConn() (net.PacketConn, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 67})
	if err != nil {
		return nil, err
	}
	slog.Info("Listening on", "addr", udpConn.LocalAddr())
	slog.Info("Broadcasting on", "addr", udpConn.RemoteAddr())
	return udpConn, nil
}
