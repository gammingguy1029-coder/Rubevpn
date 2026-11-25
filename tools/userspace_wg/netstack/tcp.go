package netstack

import (
	"fmt"
	"net"
	"sync"
	"time"

	"rubevpn/userspace_wg/services/shaper"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Idle timeout for relay connections. The deadline is refreshed on every
// successful read, so active connections are never cut off.
const tcpWaitTimeout = 5 * time.Minute

func (tun *NetTun) acceptTCP(req *tcp.ForwarderRequest) {
	if isPrivateIP(net.IP(req.ID().LocalAddress)) {
		debugf("Access to private IPv4 subnet is restricted: %s", req.ID().LocalAddress.String())
		req.Complete(true)
		return
	}
	if !acquireRelay() {
		debugf("relay limit reached, refusing TCP flow")
		req.Complete(true)
		return
	}
	defer releaseRelay()

	localAddress := req.ID().LocalAddress
	debugf("TCP> %s: %d", localAddress, req.ID().LocalPort)

	outbound, err := net.Dial("tcp", fmt.Sprintf("%s:%d", localAddress, req.ID().LocalPort))
	if err != nil {
		debugf("net.Dial() = %v", err)
		req.Complete(true)
		return
	}
	defer outbound.Close()

	var wq waiter.Queue
	ep, tcpErr := req.CreateEndpoint(&wq)
	if tcpErr != nil {
		debugf("req.CreateEndpoint() = %v", tcpErr)
		req.Complete(false)
		return
	}
	conn := gonet.NewTCPConn(&wq, ep)
	defer conn.Close()

	wg := sync.WaitGroup{}
	wg.Add(2)
	go tun.cpy(&wg, outbound, conn, 1) // tunnel -> host
	go tun.cpy(&wg, conn, outbound, 2) // host -> tunnel
	wg.Wait()
}

func (tun *NetTun) cpy(wg *sync.WaitGroup, dst, src net.Conn, _ int) {
	defer wg.Done()

	limited := shaper.NewReader(src, tun.limiter)
	buf := make([]byte, 32*1024)
	for {
		// Reset the idle deadline before each read instead of setting it after
		// the copy has already finished (which did nothing).
		_ = src.SetReadDeadline(time.Now().Add(tcpWaitTimeout))
		n, err := limited.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				debugf("relay write error: %v", writeErr)
				return
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				debugf("relay read error: %v", err)
			}
			return
		}
	}
}
