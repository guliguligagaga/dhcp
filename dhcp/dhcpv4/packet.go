package dhcpv4

import (
	o "dhcp/dhcp/options"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	BOOTREQUEST = 1
	BOOTREPLY   = 2
)

type Packet struct {
	Op      byte
	HType   byte
	HLen    byte
	Hops    byte
	XId     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  net.IP
	YIAddr  net.IP
	SIAddr  net.IP
	GIAddr  net.IP
	CHAddr  net.HardwareAddr
	SName   []byte
	File    []byte
	Options []byte
}

func (p *Packet) IsBroadcast() bool {
	return p.Flags&0x8000 != 0
}

func (p *Packet) SetBroadcast() {
	p.Flags |= 0x8000
}

func (p *Packet) ToOffer(offerIP net.IP, options *ReplyOptions) *Packet {
	offer := &Packet{
		Op:     BOOTREPLY,
		HType:  p.HType,
		HLen:   p.HLen,
		Hops:   0,
		XId:    p.XId,
		Secs:   0,
		Flags:  p.Flags,
		CIAddr: net.IPv4zero,
		YIAddr: offerIP,
		SIAddr: options.ServerIP,
		GIAddr: p.GIAddr,
		CHAddr: p.CHAddr,
	}

	offer.AddOption(OptionDHCPMessageType, []byte{DHCPOFFER})
	offer.addCommonOptions(options)

	return offer
}

func (p *Packet) ToAck(ackIP net.IP, options *ReplyOptions) *Packet {
	ack := &Packet{
		Op:     BOOTREPLY,
		HType:  p.HType,
		HLen:   p.HLen,
		Hops:   0,
		XId:    p.XId,
		Secs:   0,
		Flags:  p.Flags,
		CIAddr: p.CIAddr,
		YIAddr: ackIP,
		SIAddr: options.ServerIP,
		GIAddr: p.GIAddr,
		CHAddr: p.CHAddr,
	}

	ack.AddOption(OptionDHCPMessageType, []byte{DHCPACK})
	ack.addCommonOptions(options)

	return ack
}

func (p *Packet) ToNak(options *ReplyOptions) *Packet {
	nak := &Packet{
		Op:     BOOTREPLY,
		HType:  p.HType,
		HLen:   p.HLen,
		Hops:   0,
		XId:    p.XId,
		Secs:   0,
		Flags:  p.Flags,
		CIAddr: net.IPv4zero,
		YIAddr: net.IPv4zero,
		SIAddr: options.ServerIP,
		GIAddr: p.GIAddr,
		CHAddr: p.CHAddr,
	}

	nak.AddOption(OptionDHCPMessageType, []byte{DHCPNAK})
	nak.AddOption(OptionServerIdentifier, options.ServerIP.To4()) // Server Identifier

	return nak
}

func (p *Packet) addCommonOptions(options *ReplyOptions) {
	p.AddOption(OptionSubnetMask, options.SubnetMask)
	p.AddOption(OptionRouter, options.Router.To4())
	p.AddOption(OptionDomainNameServer, flattenIPs(options.DNS))
	p.AddOption(OptionIPAddressLeaseTime, intToBytes(uint32(options.LeaseTime.Seconds())))
	p.AddOption(OptionServerIdentifier, options.ServerIP.To4())
	p.AddOption(OptionRenewalTime, intToBytes(uint32(options.RenewalTime.Seconds())))
	p.AddOption(OptionRebindingTime, intToBytes(uint32(options.RebindingTime.Seconds())))
	if options.DomainName != "" {
		p.AddOption(OptionDomainName, []byte(options.DomainName))
	}
}

func flattenIPs(ips []net.IP) []byte {
	result := make([]byte, 0, len(ips)*4)
	for _, ip := range ips {
		result = append(result, ip.To4()...)
	}
	return result
}

func intToBytes(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

func (p *Packet) Encode() []byte {
	data := make([]byte, 240+len(p.Options))
	data[0] = p.Op
	data[1] = p.HType
	data[2] = p.HLen
	data[3] = p.Hops
	binary.BigEndian.PutUint32(data[4:8], p.XId)
	binary.BigEndian.PutUint16(data[8:10], p.Secs)
	binary.BigEndian.PutUint16(data[10:12], p.Flags)
	copy(data[12:16], p.CIAddr.To4())
	copy(data[16:20], p.YIAddr.To4())
	copy(data[20:24], p.SIAddr.To4())
	copy(data[24:28], p.GIAddr.To4())
	copy(data[28:44], p.CHAddr)
	copy(data[44:108], p.SName[:])
	copy(data[108:236], p.File[:])
	copy(data[236:240], magicCookie)
	copy(data[240:], p.Options)

	//add end opt
	data = append(data, 255)
	return data
}

func Decode(data []byte) (*Packet, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("packet too short")
	}

	packet := &Packet{
		Op:      data[0],
		HType:   data[1],
		HLen:    data[2],
		Hops:    data[3],
		XId:     binary.BigEndian.Uint32(data[4:8]),
		Secs:    binary.BigEndian.Uint16(data[8:10]),
		Flags:   binary.BigEndian.Uint16(data[10:12]),
		CIAddr:  net.IP(data[12:16]),
		YIAddr:  net.IP(data[16:20]),
		SIAddr:  net.IP(data[20:24]),
		GIAddr:  net.IP(data[24:28]),
		CHAddr:  data[28:44],
		SName:   data[44:108],
		File:    data[108:236],
		Options: data[240:],
	}
	return packet, nil
}

var magicCookie = []byte{99, 130, 83, 99}

func getDHCPMessageType(options []byte) string {
	b := strings.Builder{}
	for i := 0; i < len(options); {
		optN := options[i]
		opt := o.DHCPOptions[optN]
		if opt.Name == "End" {
			break
		}
		b.WriteString(opt.Name)
		b.WriteString(": ")
		size := int(options[i+1])
		for j := 0; j < size; j++ {
			if optN == 55 {
				b.WriteString(fmt.Sprintf("%s ;", o.DHCPOptions[options[i+2+j]].Name))
			} else {
				b.WriteString(fmt.Sprintf("%d ;", options[i+2+j]))
			}
		}

		i += int(options[i+1]) + 2

	}
	return b.String()
}

func (p *Packet) AddOption(code byte, data []byte) {
	p.Options = append(p.Options, code, byte(len(data)))
	p.Options = append(p.Options, data...)
}

func (p *Packet) GetOption(code byte) []byte {
	for i := 0; i < len(p.Options)-1; {
		if p.Options[i] == code {
			length := int(p.Options[i+1])
			return p.Options[i+2 : i+2+length]
		}
		i += int(p.Options[i+1]) + 2
	}
	return nil
}

func (p *Packet) DHCPMessageType() byte {
	t := p.GetOption(53)
	if len(t) != 1 {
		return 0
	}
	return t[0]
}
