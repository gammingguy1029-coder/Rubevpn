package netstack

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"rubevpn/userspace_wg/services/dns"
)

// services
func dnsServer(s *stack.Stack) error {
	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(net.ParseIP("10.0.0.1").To4()),
		Port: uint16(53),
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}

	go func() {
		if err := dns.Serve(udpConn); err != nil {
			debugf("dns serve error: %v", err)
		}
	}()
	return nil
}

// end services
