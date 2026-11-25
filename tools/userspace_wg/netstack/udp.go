package netstack

import (
	"context"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const idleTimeout = 30 * time.Second

func (tun *NetTun) acceptUDP(req *udp.ForwarderRequest) {
	if isPrivateIP(net.IP(req.ID().LocalAddress)) {
		debugf("Access to private IPv4 subnet is restricted: %s", req.ID().LocalAddress.String())
		return
	}
	if !acquireRelay() {
		debugf("relay limit reached, refusing UDP flow")
		return
	}

	sess := req.ID()
	debugf("acceptUDP> %s %s", sess.LocalAddress, sess.RemoteAddress)

	var wq waiter.Queue
	ep, udpErr := req.CreateEndpoint(&wq)
	if udpErr != nil {
		debugf("udpErr %v", udpErr)
		releaseRelay()
		return
	}
	client := gonet.NewUDPConn(tun.stack, &wq, ep)

	clientAddr := &net.UDPAddr{IP: net.IP([]byte(sess.RemoteAddress)), Port: int(sess.RemotePort)}
	remoteAddr := &net.UDPAddr{IP: net.IP([]byte(sess.LocalAddress)), Port: int(sess.LocalPort)}

	if remoteAddr.Port == 53 && tun.isLocal(sess.LocalAddress) {
		remoteAddr.Port = 53
		remoteAddr.IP = net.ParseIP("127.0.0.1")
	}

	// Bind an ephemeral local port. Binding to the client's source port caused
	// collisions under load and forced a slow fallback for every flow.
	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		debugf("Failed to bind UDP proxy socket: %v", err)
		releaseRelay()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		tun.proxy(ctx, cancel, client, clientAddr, proxyConn)
		releaseRelay()
	}()
	go tun.proxy(ctx, cancel, proxyConn, remoteAddr, client)
}

func (tun *NetTun) proxy(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn,
	dstAddr net.Addr, src net.PacketConn) {
	defer cancel()
	buf := make([]byte, tun.mtu)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, srcAddr, err := src.ReadFrom(buf)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return
			} else if err != nil {
				if ctx.Err() == nil {
					debugf("Failed to read packet from %s: %v", srcAddr, err)
				}
				return
			}
			if n > 0 {
				if err := tun.limiter.WaitN(ctx, n); err != nil {
					debugf("Shaper error: %v", err)
					return
				}
			}
			if _, err := dst.WriteTo(buf[:n], dstAddr); err != nil {
				if ctx.Err() == nil {
					debugf("Failed to write packet to %s: %v", dstAddr, err)
				}
				return
			}
		}
	}
}
