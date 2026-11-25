// Experimental throughput check: a userspace WireGuard peer downloads a
// fixed number of bytes over HTTP through the tunnel and reports the rate.
// Keys are supplied through environment variables and are never logged.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"time"

	"rubevpn/userspace_wg/netstack"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	testBytes = 10 * 1024 * 1024 // 10 MB gives TCP time to ramp up
	timeout   = 45 * time.Second
)

var downloadURLs = []string{
	"https://speed.cloudflare.com/__down?bytes=10485760",
	"https://speed.cloudflare.com/__down?bytes=10000000",
}

func key(name, value string) string {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		log.Fatalf("%s must be a 32-byte base64 WireGuard key", name)
	}
	return hex.EncodeToString(raw)
}

// download fetches exactly testBytes and returns the count and elapsed time.
func download(ctx context.Context, client *http.Client, url string) (int64, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	n, err := io.CopyN(io.Discard, resp.Body, testBytes)
	elapsed := time.Since(start)
	if err != nil {
		return n, elapsed, err
	}
	return n, elapsed, nil
}

func main() {
	privateKey := key("RUBEVPN_WG_PRIVATE_KEY", os.Getenv("RUBEVPN_WG_PRIVATE_KEY"))
	serverKey := key("RUBEVPN_WG_SERVER_PUBLIC_KEY", os.Getenv("RUBEVPN_WG_SERVER_PUBLIC_KEY"))
	endpoint := os.Getenv("RUBEVPN_TEST_ENDPOINT")
	if endpoint == "" {
		log.Fatal("RUBEVPN_TEST_ENDPOINT is required")
	}

	localRaw := os.Getenv("RUBEVPN_WG_LOCAL_ADDRESS")
	if localRaw == "" {
		localRaw = "10.0.0.3"
	}
	localAddress, err := netip.ParseAddr(localRaw)
	if err != nil || !localAddress.Is4() {
		log.Fatal("RUBEVPN_WG_LOCAL_ADDRESS must be a valid IPv4 address")
	}

	tun, ns, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddress},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1420,
	)
	if err != nil {
		log.Fatal(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	settings := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privateKey, serverKey, endpoint,
	)
	if err := dev.IpcSet(settings); err != nil {
		log.Fatal(err)
	}
	dev.Up()
	defer func() {
		dev.Down()
		dev.Close()
		<-dev.Wait()
	}()

	// Allow time for the WireGuard handshake to complete through the relay.
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:       nil, // ignore any host HTTP_PROXY; all traffic must use the tunnel
			DialContext: ns.DialContext,
		},
		Timeout: timeout,
	}

	var lastErr error
	for _, url := range downloadURLs {
		n, elapsed, err := download(ctx, client, url)
		if err != nil {
			lastErr = err
			continue
		}
		mbps := float64(n) * 8 / elapsed.Seconds() / 1_000_000
		fmt.Printf("SPEEDTEST_OK mbps=%.2f bytes=%d\n", mbps, n)
		return
	}
	fmt.Printf("SPEEDTEST_FAILED error=%v\n", lastErr)
	os.Exit(1)
}
