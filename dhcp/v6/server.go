package v6

import "net"

type DHCPv6 struct {
	ipPool *ipPool
	config *Config

	udpConn net.PacketConn

	clientPort int
	serverPort int
}

func MakeDHCPv6(c *Config) (*DHCPv6, error) {
	pool := newIpPool()
	return &DHCPv6{
		ipPool:     pool,
		config:     c,
		clientPort: 546,
		serverPort: 547,
	}, nil
}

func (s *DHCPv6) Start() {
	go s.startReadConn()
}
