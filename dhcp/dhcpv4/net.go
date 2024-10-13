package dhcpv4

import "net"

func notEmpty(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() {
		return false
	}
	return true
}

func ip4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP4(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func convertMACToUint64(mac net.HardwareAddr) uint64 {
	return uint64(mac[0])<<40 | uint64(mac[1])<<32 | uint64(mac[2])<<24 | uint64(mac[3])<<16 | uint64(mac[4])<<8 | uint64(mac[5])
}

func convertIPToUint64(ip net.IP) uint64 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint64(ip[0])<<24 | uint64(ip[1])<<16 | uint64(ip[2])<<8 | uint64(ip[3])
}
