package v6

import (
	"net"
	"time"
)

type Config struct {
	AddrPool         net.IP
	LeaseTime        time.Duration
	DNSServers       []net.IP
	DomainName       string
	PrefixDelegation bool
	RapidCommit      bool
	InfoRefreshRate  time.Duration
}
