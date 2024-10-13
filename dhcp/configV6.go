package dhcp

import (
	"net"
	"time"
)

type ConfigV6 struct {
	AddressPool      net.IP
	Lease            time.Duration
	DNSServer        []net.IP
	DomainName       string
	PrefixDelegation bool
	RapidCommit      bool
	InfoRefreshTime  time.Duration
}
