package netstack

import (
	"context"
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Dial opens a TCP connection through the userspace stack (and therefore
// through the WireGuard tunnel) instead of the host network.
func (n *Net) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

// DialContext is Dial with cancellation and deadline support. Only IPv4 TCP
// is supported: the userspace stack is created with the IPv4 protocol only.
func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("netstack: unsupported network %q", network)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	remote, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		return nil, err
	}
	if remote.IP == nil || remote.IP.To4() == nil {
		return nil, fmt.Errorf("netstack: no IPv4 address for %q", address)
	}

	local := tcpip.FullAddress{NIC: 1}
	tun := (*NetTun)(n)
	if len(tun.localAddresses) > 0 {
		if ip := tun.localAddresses[0].Unmap().AsSlice(); len(ip) == 4 {
			local.Addr = tcpip.Address(ip)
		}
	}
	remoteAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(remote.IP.To4()),
		Port: uint16(remote.Port),
	}

	conn, err := gonet.DialTCPWithBind(ctx, tun.stack, local, remoteAddr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
