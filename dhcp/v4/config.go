package v4

import (
	"net"
	"time"
)

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
