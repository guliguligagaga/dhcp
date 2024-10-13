//go:build linux

package dhcp

import (
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"
)

type linuxConn struct {
	conn net.PacketConn
	fd   int
	addr *syscall.SockaddrLinklayer
}

func (l *linuxConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if v, ok := addr.(*net.UDPAddr); ok {
		return l.conn.WriteTo(p, v)
	}

	if err = syscall.Sendto(l.fd, p, 0, l.addr); err != nil {
		return 0, fmt.Errorf("failed to send packet: %v", err)
	}
	return 0, nil
}

func (l *linuxConn) SetReadDeadline(t time.Time) error {
	return l.conn.SetReadDeadline(t)
}

func (l *linuxConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return l.conn.ReadFrom(p)
}

func (l *linuxConn) Close() {
	err1 := l.conn.Close()
	err2 := syscall.Close(l.fd)
	if err1 != nil || err2 != nil {
		slog.Error("Failed to close connection", "err1", err1, "err2", err2)
	}
}

func (s *Server) buildConn() (*linuxConn, error) {
	iface, err := getInterface()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %v", err)
	}

	fd, err := syscall.Socket(0x11, 0x3, int(htons(0x3)))
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %v", err)
	}

	if err = syscall.SetsockoptInt(fd, 0x1, 0x6, 1); err != nil {
		return nil, fmt.Errorf("cannot set broadcasting on socket: %v", err)
	}
	if err = syscall.SetsockoptInt(fd, 0x1, 0x2, 1); err != nil {
		return nil, fmt.Errorf("cannot set reuseaddr on socket: %v", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ALL,
		Ifindex:  iface.Index,
	}

	if err = syscall.Bind(fd, &addr); err != nil {
		return nil, fmt.Errorf("failed to bind to device: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 67})
	if err != nil {
		return nil, err
	}
	slog.Info("Listening on", "addr", udpConn.LocalAddr())
	slog.Info("Broadcasting on", "addr", udpConn.RemoteAddr())

	return &linuxConn{
		conn: udpConn,
		fd:   fd,
		addr: &addr,
	}, nil
}

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}
