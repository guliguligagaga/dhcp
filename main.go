package main

import (
	"dhcp/dhcp"
	"dhcp/dhcp/v4"
	"net"
	"time"
)

func main() {
	config := v4.Config{
		Start:         net.IP{172, 20, 0, 10},
		End:           net.IP{172, 20, 0, 20},
		Subnet:        net.IPNet{IP: net.IP{172, 20, 0, 0}, Mask: net.IPMask{255, 255, 0, 0}},
		Lease:         10 * time.Minute,
		RenewalTime:   5 * time.Minute, // 50%
		RebindingTime: 8 * time.Minute, // 80%
		DNS:           []net.IP{{8, 8, 8, 8}, {8, 8, 4, 4}},
		Router:        net.IP{172, 20, 0, 1},
		ServerIP:      net.IP{172, 20, 0, 2},
		DomainName:    "DHCP TEST",
	}
	server, err := dhcp.NewServer(&config)
	if err != nil {
		panic(err)
	}
	server.Run()
}
