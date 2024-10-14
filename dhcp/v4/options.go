package v4

import (
	"net"
	"time"
)

const (
	// Commonly used DHCP options
	OptionSubnetMask           byte = 1
	OptionRouter                    = 3
	OptionDomainNameServer          = 6
	OptionHostname                  = 12
	OptionDomainName                = 15
	OptionBroadcastAddress          = 28
	OptionNetworkTimeProtocol       = 42
	OptionVendorSpecific            = 43
	OptionRequestedIPAddress        = 50
	OptionIPAddressLeaseTime        = 51
	OptionDHCPMessageType           = 53
	OptionServerIdentifier          = 54
	OptionParameterRequestList      = 55
	OptionRenewalTime               = 58
	OptionRebindingTime             = 59
	OptionClassIdentifier           = 60
	OptionClientIdentifier          = 61
	OptionTFTPServerName            = 66
	OptionBootfileName              = 67
	OptionUserClass                 = 77
	OptionClientFQDN                = 81
	OptionDHCPAgentOptions          = 82
	OptionDomainSearch              = 119
	OptionClasslessStaticRoute      = 121
	OptionEnd                       = 255
)

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
