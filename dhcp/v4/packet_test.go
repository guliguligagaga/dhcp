package v4

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestPacketIsBroadcast(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint16
		expected bool
	}{
		{"Broadcast", 0x8000, true},
		{"Not Broadcast", 0x0000, false},
		{"Mixed Flags", 0x8001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{Flags: tt.flags}
			if got := p.IsBroadcast(); got != tt.expected {
				t.Errorf("IsBroadcast() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPacketSetBroadcast(t *testing.T) {
	tests := []struct {
		name        string
		initialFlag uint16
	}{
		{"Already Broadcast", 0x8000},
		{"Not Broadcast", 0x0000},
		{"Mixed Flags", 0x0001},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{Flags: tt.initialFlag}
			p.SetBroadcast()
			if !p.IsBroadcast() {
				t.Errorf("SetBroadcast() did not set broadcast flag")
			}
			if p.Flags&0x8000 == 0 {
				t.Errorf("SetBroadcast() did not set the correct bit")
			}
		})
	}
}

func TestPacketToOffer(t *testing.T) {
	request := &Packet{
		Op:     BOOTREQUEST,
		HType:  1,
		HLen:   6,
		XId:    12345,
		Flags:  0x8000,
		GIAddr: net.IPv4(192, 168, 1, 1),
		CHAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}

	offerIP := net.IPv4(192, 168, 1, 100)
	options := &ReplyOptions{
		ServerIP:      net.IPv4(192, 168, 1, 1),
		SubnetMask:    net.IPv4Mask(255, 255, 255, 0),
		Router:        net.IPv4(192, 168, 1, 1),
		DNS:           []net.IP{net.IPv4(8, 8, 8, 8)},
		LeaseTime:     1 * time.Hour,
		RenewalTime:   30 * time.Minute,
		RebindingTime: 45 * time.Minute,
		DomainName:    "example.com",
	}

	offer := request.ToOffer(offerIP, options)

	if offer.Op != BOOTREPLY {
		t.Errorf("Expected Op to be BOOTREPLY, got %d", offer.Op)
	}
	if !offer.YIAddr.Equal(offerIP) {
		t.Errorf("Expected YIAddr to be %v, got %v", offerIP, offer.YIAddr)
	}
	if !offer.SIAddr.Equal(options.ServerIP) {
		t.Errorf("Expected SIAddr to be %v, got %v", options.ServerIP, offer.SIAddr)
	}
	if !bytes.Equal(offer.CHAddr, request.CHAddr) {
		t.Errorf("Expected CHAddr to be %v, got %v", request.CHAddr, offer.CHAddr)
	}

	// Check DHCP Message Type option
	if msgType := offer.GetOption(OptionDHCPMessageType); !bytes.Equal(msgType, []byte{DHCPOFFER}) {
		t.Errorf("Expected DHCP Message Type to be DHCPOFFER, got %v", msgType)
	}

	// Check other options
	checkCommonOptions(t, offer, options)
}

func TestPacketToAck(t *testing.T) {
	request := &Packet{
		Op:     BOOTREQUEST,
		HType:  1,
		HLen:   6,
		XId:    12345,
		Flags:  0x8000,
		CIAddr: net.IPv4(192, 168, 1, 100),
		GIAddr: net.IPv4(192, 168, 1, 1),
		CHAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}

	ackIP := net.IPv4(192, 168, 1, 100)
	options := &ReplyOptions{
		ServerIP:      net.IPv4(192, 168, 1, 1),
		SubnetMask:    net.IPv4Mask(255, 255, 255, 0),
		Router:        net.IPv4(192, 168, 1, 1),
		DNS:           []net.IP{net.IPv4(8, 8, 8, 8)},
		LeaseTime:     1 * time.Hour,
		RenewalTime:   30 * time.Minute,
		RebindingTime: 45 * time.Minute,
		DomainName:    "example.com",
	}

	ack := request.ToAck(ackIP, options)

	if ack.Op != BOOTREPLY {
		t.Errorf("Expected Op to be BOOTREPLY, got %d", ack.Op)
	}
	if !ack.YIAddr.Equal(ackIP) {
		t.Errorf("Expected YIAddr to be %v, got %v", ackIP, ack.YIAddr)
	}
	if !ack.SIAddr.Equal(options.ServerIP) {
		t.Errorf("Expected SIAddr to be %v, got %v", options.ServerIP, ack.SIAddr)
	}
	if !bytes.Equal(ack.CHAddr, request.CHAddr) {
		t.Errorf("Expected CHAddr to be %v, got %v", request.CHAddr, ack.CHAddr)
	}

	// Check DHCP Message Type option
	if msgType := ack.GetOption(OptionDHCPMessageType); !bytes.Equal(msgType, []byte{DHCPACK}) {
		t.Errorf("Expected DHCP Message Type to be DHCPACK, got %v", msgType)
	}

	// Check other options
	checkCommonOptions(t, ack, options)
}

func TestPacketToNak(t *testing.T) {
	request := &Packet{
		Op:     BOOTREQUEST,
		HType:  1,
		HLen:   6,
		XId:    12345,
		Flags:  0x8000,
		GIAddr: net.IPv4(192, 168, 1, 1),
		CHAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}

	options := &ReplyOptions{
		ServerIP: net.IPv4(192, 168, 1, 1),
	}

	nak := request.ToNak(options)

	if nak.Op != BOOTREPLY {
		t.Errorf("Expected Op to be BOOTREPLY, got %d", nak.Op)
	}
	if !nak.YIAddr.Equal(net.IPv4zero) {
		t.Errorf("Expected YIAddr to be 0.0.0.0, got %v", nak.YIAddr)
	}
	if !nak.SIAddr.Equal(options.ServerIP) {
		t.Errorf("Expected SIAddr to be %v, got %v", options.ServerIP, nak.SIAddr)
	}
	if !bytes.Equal(nak.CHAddr, request.CHAddr) {
		t.Errorf("Expected CHAddr to be %v, got %v", request.CHAddr, nak.CHAddr)
	}

	// Check DHCP Message Type option
	if msgType := nak.GetOption(OptionDHCPMessageType); !bytes.Equal(msgType, []byte{DHCPNAK}) {
		t.Errorf("Expected DHCP Message Type to be DHCPNAK, got %v", msgType)
	}

	// Check Server Identifier option
	if serverID := nak.GetOption(OptionServerIdentifier); !bytes.Equal(serverID, options.ServerIP.To4()) {
		t.Errorf("Expected Server Identifier to be %v, got %v", options.ServerIP.To4(), serverID)
	}
}

func TestPacketEncodeDecode(t *testing.T) {
	hw, _ := net.ParseMAC("00:11:22:33:44:55")
	original := &Packet{
		Op:     BOOTREQUEST,
		HType:  1,
		HLen:   6,
		Hops:   0,
		XId:    12345,
		Secs:   60,
		Flags:  0x8000,
		CIAddr: net.IPv4(192, 168, 1, 100),
		YIAddr: net.IPv4(0, 0, 0, 0),
		SIAddr: net.IPv4(192, 168, 1, 1),
		GIAddr: net.IPv4(192, 168, 1, 1),
		CHAddr: hw,
		SName:  make([]byte, 64),
		File:   make([]byte, 128),
	}

	original.AddOption(OptionDHCPMessageType, []byte{DHCPDISCOVER})
	original.AddOption(OptionParameterRequestList, []byte{1, 3, 6, 15})

	encoded := original.Encode()
	decoded, err := Decode(encoded)

	if err != nil {
		t.Fatalf("Failed to decode packet: %v", err)
	}

	// Compare fields
	if decoded.Op != original.Op {
		t.Errorf("Op mismatch: got %d, want %d", decoded.Op, original.Op)
	}
	if decoded.HType != original.HType {
		t.Errorf("HType mismatch: got %d, want %d", decoded.HType, original.HType)
	}
	if decoded.HLen != original.HLen {
		t.Errorf("HLen mismatch: got %d, want %d", decoded.HLen, original.HLen)
	}
	if decoded.Hops != original.Hops {
		t.Errorf("Hops mismatch: got %d, want %d", decoded.Hops, original.Hops)
	}
	if decoded.XId != original.XId {
		t.Errorf("XId mismatch: got %d, want %d", decoded.XId, original.XId)
	}
	if decoded.Secs != original.Secs {
		t.Errorf("Secs mismatch: got %d, want %d", decoded.Secs, original.Secs)
	}
	if decoded.Flags != original.Flags {
		t.Errorf("Flags mismatch: got %d, want %d", decoded.Flags, original.Flags)
	}
	if !decoded.CIAddr.Equal(original.CIAddr) {
		t.Errorf("CIAddr mismatch: got %v, want %v", decoded.CIAddr, original.CIAddr)
	}
	if !decoded.YIAddr.Equal(original.YIAddr) {
		t.Errorf("YIAddr mismatch: got %v, want %v", decoded.YIAddr, original.YIAddr)
	}
	if !decoded.SIAddr.Equal(original.SIAddr) {
		t.Errorf("SIAddr mismatch: got %v, want %v", decoded.SIAddr, original.SIAddr)
	}
	if !decoded.GIAddr.Equal(original.GIAddr) {
		t.Errorf("GIAddr mismatch: got %v, want %v", decoded.GIAddr, original.GIAddr)
	}
	if !bytes.Equal(decoded.CHAddr[:6], original.CHAddr) {
		t.Errorf("CHAddr mismatch: got %v, want %v", decoded.CHAddr[:6], original.CHAddr)
	}

	// Check options
	if !bytes.Equal(decoded.GetOption(OptionDHCPMessageType), []byte{DHCPDISCOVER}) {
		t.Errorf("DHCP Message Type option mismatch")
	}
	if !bytes.Equal(decoded.GetOption(OptionParameterRequestList), []byte{1, 3, 6, 15}) {
		t.Errorf("Parameter Request List option mismatch")
	}
}

func TestPacketGetOption(t *testing.T) {
	p := &Packet{}
	p.AddOption(OptionDHCPMessageType, []byte{DHCPDISCOVER})
	p.AddOption(OptionParameterRequestList, []byte{1, 3, 6, 15})

	tests := []struct {
		name     string
		option   byte
		expected []byte
	}{
		{"Existing Option", OptionDHCPMessageType, []byte{DHCPDISCOVER}},
		{"Another Existing Option", OptionParameterRequestList, []byte{1, 3, 6, 15}},
		{"Non-existent Option", 255, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.GetOption(tt.option)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("GetOption(%d) = %v, want %v", tt.option, got, tt.expected)
			}
		})
	}
}

func TestPacketDHCPMessageType(t *testing.T) {
	tests := []struct {
		name     string
		option   []byte
		expected byte
	}{
		{"DHCPDISCOVER", []byte{DHCPDISCOVER}, DHCPDISCOVER},
		{"DHCPOFFER", []byte{DHCPOFFER}, DHCPOFFER},
		{"DHCPREQUEST", []byte{DHCPREQUEST}, DHCPREQUEST},
		{"DHCPDECLINE", []byte{DHCPDECLINE}, DHCPDECLINE},
		{"DHCPACK", []byte{DHCPACK}, DHCPACK},
		{"DHCPNAK", []byte{DHCPNAK}, DHCPNAK},
		{"DHCPRELEASE", []byte{DHCPRELEASE}, DHCPRELEASE},
		{"DHCPINFORM", []byte{DHCPINFORM}, DHCPINFORM},
		{"Invalid Length", []byte{}, 0},
		{"Multiple Values", []byte{DHCPDISCOVER, DHCPOFFER}, 0},
		{"No Option", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{}
			if tt.option != nil {
				p.AddOption(OptionDHCPMessageType, tt.option)
			}
			got := p.DHCPMessageType()
			if got != tt.expected {
				t.Errorf("DHCPMessageType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDecodeEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectedErr string
	}{
		{"Empty Packet", []byte{}, "packet too short"},
		{"Incomplete Packet", make([]byte, 239), "packet too short"},
		{"Minimum Valid Packet", make([]byte, 240), ""},
		{"Packet with Options", append(make([]byte, 240), 1, 1, 1), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.data)
			if tt.expectedErr == "" && err != nil {
				t.Errorf("Decode() unexpected error: %v", err)
			} else if tt.expectedErr != "" && (err == nil || err.Error() != tt.expectedErr) {
				t.Errorf("Decode() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}

func TestAddOptionEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		code     byte
		data     []byte
		expected int
	}{
		{"Empty Data", 1, []byte{}, 2},
		{"Nil Data", 1, nil, 2},
		{"Single Byte", 1, []byte{1}, 3},
		{"Multiple Bytes", 1, []byte{1, 2, 3}, 5},
		{"Large Option", 1, make([]byte, 255), 257},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{}
			p.AddOption(tt.code, tt.data)
			if len(p.Options) != tt.expected {
				t.Errorf("AddOption() resulted in Options length = %d, want %d", len(p.Options), tt.expected)
			}
			if p.Options[0] != tt.code {
				t.Errorf("AddOption() set code = %d, want %d", p.Options[0], tt.code)
			}
			if p.Options[1] != byte(len(tt.data)) {
				t.Errorf("AddOption() set length = %d, want %d", p.Options[1], len(tt.data))
			}
		})
	}
}

func TestGetOptionEdgeCases(t *testing.T) {
	p := &Packet{}
	p.AddOption(1, []byte{1, 2, 3})
	p.AddOption(2, []byte{4, 5})
	p.AddOption(3, []byte{})

	tests := []struct {
		name     string
		code     byte
		expected []byte
	}{
		{"Existing Option", 1, []byte{1, 2, 3}},
		{"Another Existing Option", 2, []byte{4, 5}},
		{"Empty Option", 3, []byte{}},
		{"Non-existent Option", 4, nil},
		{"Option at End", 3, []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.GetOption(tt.code)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("GetOption(%d) = %v, want %v", tt.code, got, tt.expected)
			}
		})
	}
}

func TestFlattenIPs(t *testing.T) {
	tests := []struct {
		name     string
		ips      []net.IP
		expected []byte
	}{
		{"Single IP", []net.IP{net.IPv4(192, 168, 1, 1)}, []byte{192, 168, 1, 1}},
		{"Multiple IPs", []net.IP{net.IPv4(192, 168, 1, 1), net.IPv4(8, 8, 8, 8)}, []byte{192, 168, 1, 1, 8, 8, 8, 8}},
		{"Empty List", []net.IP{}, []byte{}},
		//{"IPv6 Addresses", []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}, []byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flattenIPs(tt.ips)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("flattenIPs() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIntToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected []byte
	}{
		{"Zero", 0, []byte{0, 0, 0, 0}},
		{"Small Number", 1, []byte{0, 0, 0, 1}},
		{"Large Number", 4294967295, []byte{255, 255, 255, 255}},
		{"Random Number", 305419896, []byte{18, 52, 86, 120}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intToBytes(tt.input)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("intToBytes(%d) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGetDHCPMessageType(t *testing.T) {
	tests := []struct {
		name     string
		options  []byte
		expected string
	}{
		{"Empty Options", []byte{}, ""},
		{"Single Option", []byte{53, 1, 1}, "DHCP Msg Type: 1 ;"},
		{"Multiple Options", []byte{53, 1, 1, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 1, 1}, "DHCP Msg Type: 1 ;Subnet Mask: 255 ;255 ;255 ;0 ;Router: 192 ;168 ;1 ;1 ;"},
		{"Parameter Request List", []byte{55, 3, 1, 3, 6}, "Parameter List: Subnet Mask ;Router ;Domain Server ;"},
		{"Invalid Option", []byte{255}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getDHCPMessageType(tt.options)
			if got != tt.expected {
				t.Errorf("getDHCPMessageType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func checkCommonOptions(t *testing.T, p *Packet, options *ReplyOptions) {
	t.Helper()

	if subnet := p.GetOption(OptionSubnetMask); !bytes.Equal(subnet, options.SubnetMask) {
		t.Errorf("Expected Subnet Mask to be %v, got %v", options.SubnetMask, subnet)
	}

	if router := p.GetOption(OptionRouter); !bytes.Equal(router, options.Router.To4()) {
		t.Errorf("Expected Router to be %v, got %v", options.Router.To4(), router)
	}

	if dns := p.GetOption(OptionDomainNameServer); !bytes.Equal(dns, flattenIPs(options.DNS)) {
		t.Errorf("Expected DNS to be %v, got %v", flattenIPs(options.DNS), dns)
	}

	if leaseTime := p.GetOption(OptionIPAddressLeaseTime); !bytes.Equal(leaseTime, intToBytes(uint32(options.LeaseTime.Seconds()))) {
		t.Errorf("Expected Lease Time to be %v, got %v", intToBytes(uint32(options.LeaseTime.Seconds())), leaseTime)
	}

	if serverID := p.GetOption(OptionServerIdentifier); !bytes.Equal(serverID, options.ServerIP.To4()) {
		t.Errorf("Expected Server Identifier to be %v, got %v", options.ServerIP.To4(), serverID)
	}

	if renewalTime := p.GetOption(OptionRenewalTime); !bytes.Equal(renewalTime, intToBytes(uint32(options.RenewalTime.Seconds()))) {
		t.Errorf("Expected Renewal Time to be %v, got %v", intToBytes(uint32(options.RenewalTime.Seconds())), renewalTime)
	}

	if rebindingTime := p.GetOption(OptionRebindingTime); !bytes.Equal(rebindingTime, intToBytes(uint32(options.RebindingTime.Seconds()))) {
		t.Errorf("Expected Rebinding Time to be %v, got %v", intToBytes(uint32(options.RebindingTime.Seconds())), rebindingTime)
	}

	if domainName := p.GetOption(OptionDomainName); !bytes.Equal(domainName, []byte(options.DomainName)) {
		t.Errorf("Expected Domain Name to be %v, got %v", []byte(options.DomainName), domainName)
	}
}
