package v4

import (
	"fmt"
	"net"
	"testing"
	"time"
)

type mockConn struct {
	p []byte
}

func (m *mockConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}

func (m *mockConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {

	if _, ok := addr.(*net.UDPAddr); ok {
		m.p = p
		return len(p), nil
	}
	m.p = p[42:]
	return len(m.p), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) sentPacket() *Packet {
	if m.p == nil {
		return nil
	}
	decode, _ := Decode(m.p)
	return decode
}

func TestHandleRequest(t *testing.T) {
	cfg := &Config{
		Start:         net.ParseIP("192.168.1.100"),
		End:           net.ParseIP("192.168.1.200"),
		Subnet:        net.IPNet{IP: net.ParseIP("192.168.1.0"), Mask: net.IPv4Mask(255, 255, 255, 0)},
		Lease:         time.Hour,
		RenewalTime:   30 * time.Minute,
		RebindingTime: 45 * time.Minute,
		DNS:           []net.IP{net.ParseIP("8.8.8.8")},
		Router:        net.ParseIP("192.168.1.1"),
		ServerIP:      net.ParseIP("192.168.1.2"),
		DomainName:    "example.com",
	}

	mockAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 68}

	createPacket := func(messageType byte, clientIP net.IP, requestedIP net.IP, serverIP net.IP) *Packet {
		options := []byte{
			OptionDHCPMessageType, 1, messageType,
		}
		if !requestedIP.IsUnspecified() {
			options = append(options, OptionRequestedIPAddress, 4)
			options = append(options, requestedIP.To4()...)
		}
		if !serverIP.IsUnspecified() {
			options = append(options, OptionServerIdentifier, 4)
			options = append(options, serverIP.To4()...)
		}
		return &Packet{
			Op:      BOOTREQUEST,
			HType:   1,
			HLen:    6,
			Hops:    0,
			XId:     1234,
			Secs:    0,
			Flags:   0,
			CIAddr:  clientIP,
			YIAddr:  net.IPv4zero,
			SIAddr:  serverIP,
			GIAddr:  net.IPv4zero,
			CHAddr:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			Options: options,
		}
	}

	testCases := []struct {
		name            string
		packet          *Packet
		expectedState   int
		expectResponse  bool
		setup           func(*DHCPv4)
		additionalCheck func(*testing.T, *Packet)
	}{
		{
			name:           "SELECTING - Valid request",
			packet:         createPacket(DHCPREQUEST, net.IPv4zero, net.ParseIP("192.168.1.100"), cfg.ServerIP),
			expectedState:  selecting,
			expectResponse: true,
			setup: func(s *DHCPv4) {
				s.bindings[convertMACToUint64(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})] = &binding{
					IP:         net.ParseIP("192.168.1.100"),
					MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					Expiration: time.Now().Add(time.Hour),
				}
			},
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPACK {
					t.Errorf("Expected DHCPACK for valid SELECTING request")
				}
			},
		},
		{
			name:           "SELECTING - Different server",
			packet:         createPacket(DHCPREQUEST, net.IPv4zero, net.ParseIP("192.168.1.100"), net.ParseIP("192.168.1.3")),
			expectedState:  selecting,
			expectResponse: false,
		},
		{
			name:           "INIT_REBOOT - Valid request",
			packet:         createPacket(DHCPREQUEST, net.IPv4zero, net.ParseIP("192.168.1.100"), net.IPv4zero),
			expectedState:  initReboot,
			expectResponse: true,
			setup: func(s *DHCPv4) {
				s.bindings[convertMACToUint64(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})] = &binding{
					IP:         net.ParseIP("192.168.1.100"),
					MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					Expiration: time.Now().Add(time.Hour),
				}
			},
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPACK {
					t.Errorf("Expected DHCPACK for valid INIT_REBOOT request")
				}
			},
		},
		{
			name:           "RENEWING - Valid request",
			packet:         createPacket(DHCPREQUEST, net.ParseIP("192.168.1.100"), net.IPv4zero, net.IPv4zero),
			expectedState:  renewing,
			expectResponse: true,
			setup: func(s *DHCPv4) {
				s.bindings[convertMACToUint64(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})] = &binding{
					IP:         net.ParseIP("192.168.1.100"),
					MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					Expiration: time.Now().Add(time.Hour),
				}
			},
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPACK {
					t.Errorf("Expected DHCPACK for valid RENEWING request")
				}
			},
		},
		{
			name:           "REBINDING - Valid request",
			packet:         createPacket(DHCPREQUEST, net.ParseIP("192.168.1.100"), net.IPv4zero, net.IPv4zero),
			expectedState:  rebinding,
			expectResponse: true,
			setup: func(s *DHCPv4) {
				s.bindings[convertMACToUint64(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})] = &binding{
					IP:         net.ParseIP("192.168.1.100"),
					MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					Expiration: time.Now().Add(time.Hour),
				}
			},
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPACK {
					t.Errorf("Expected DHCPACK for valid REBINDING request")
				}
			},
		},
		{
			name:           "Invalid state",
			packet:         createPacket(DHCPREQUEST, net.ParseIP("192.168.1.100"), net.ParseIP("192.168.1.100"), net.ParseIP("192.168.1.2")),
			expectedState:  -1,
			expectResponse: false,
		},
		{
			name:           "SELECTING - IP not in server pool",
			packet:         createPacket(DHCPREQUEST, net.IPv4zero, net.ParseIP("192.168.2.100"), cfg.ServerIP),
			expectedState:  selecting,
			expectResponse: true,
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPNAK {
					t.Errorf("Expected DHCPNAK for IP not in server pool")
				}
			},
		},
		{
			name:           "INIT_REBOOT - Unknown client",
			packet:         createPacket(DHCPREQUEST, net.IPv4zero, net.ParseIP("192.168.1.150"), net.IPv4zero),
			expectedState:  initReboot,
			expectResponse: true,
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPNAK {
					t.Errorf("Expected DHCPNAK for unknown client in INIT_REBOOT")
				}
			},
		},
		{
			name:           "RENEWING - Expired lease",
			packet:         createPacket(DHCPREQUEST, net.ParseIP("192.168.1.100"), net.IPv4zero, net.IPv4zero),
			expectedState:  renewing,
			expectResponse: true,
			setup: func(s *DHCPv4) {
				s.bindings[convertMACToUint64(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})] = &binding{
					IP:         net.ParseIP("192.168.1.100"),
					MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					Expiration: time.Now().Add(-time.Hour),
				}
			},
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPNAK {
					t.Errorf("Expected DHCPNAK for expired lease in RENEWING")
				}
			},
		},
		{
			name:           "REBINDING - IP conflict",
			packet:         createPacket(DHCPREQUEST, net.ParseIP("192.168.1.100"), net.IPv4zero, net.IPv4zero),
			expectedState:  rebinding,
			expectResponse: true,
			setup: func(s *DHCPv4) {
				s.bindings[convertMACToUint64(net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})] = &binding{
					IP:         net.ParseIP("192.168.1.100"),
					MAC:        net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
					Expiration: time.Now().Add(time.Hour),
				}
			},
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPNAK {
					t.Errorf("Expected DHCPNAK for IP conflict in REBINDING")
				}
			},
		},
		{
			name:           "SELECTING - Full IP pool",
			packet:         createPacket(DHCPREQUEST, net.IPv4zero, net.ParseIP("192.168.1.150"), cfg.ServerIP),
			expectedState:  selecting,
			expectResponse: true,
			setup: func(s *DHCPv4) {
				for i := 100; i <= 200; i++ {
					ip := net.ParseIP(fmt.Sprintf("192.168.1.%d", i))
					s.bindings[uint64(i)] = &binding{
						IP:         ip,
						MAC:        net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, byte(i)},
						Expiration: time.Now().Add(time.Hour),
					}
				}
			},
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPNAK {
					t.Errorf("Expected DHCPNAK when IP pool is full")
				}
			},
		},
		{
			name:           "INIT_REBOOT - Requested IP doesn't match binding",
			packet:         createPacket(DHCPREQUEST, net.IPv4zero, net.ParseIP("192.168.1.150"), net.IPv4zero),
			expectedState:  initReboot,
			expectResponse: true,
			setup: func(s *DHCPv4) {
				s.bindings[convertMACToUint64(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})] = &binding{
					IP:         net.ParseIP("192.168.1.100"), // Different from requested IP
					MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					Expiration: time.Now().Add(time.Hour),
				}
			},
			additionalCheck: func(t *testing.T, p *Packet) {
				if p.DHCPMessageType() != DHCPNAK {
					t.Errorf("Expected DHCPNAK when requested IP doesn't match binding")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := MakeDHCPv4(cfg)
			server.udpConn = &mockConn{}

			if tc.setup != nil {
				tc.setup(server)
			}

			server.handleRequest(tc.packet, mockAddr)
			sentPacket := server.udpConn.(*mockConn).sentPacket()

			if tc.expectResponse && sentPacket == nil {
				t.Errorf("Expected a response packet, but none was sent")
			} else if !tc.expectResponse && sentPacket != nil {
				t.Errorf("Did not expect a response packet, but one was sent")
			}

			if sentPacket != nil && tc.additionalCheck != nil {
				tc.additionalCheck(t, sentPacket)
			}
		})
	}
}
