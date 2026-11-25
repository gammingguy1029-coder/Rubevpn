// Experimental RubeVPN userspace WireGuard server (no TUN, no admin rights).
// Keys are supplied through environment variables and are never logged.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"rubevpn/userspace_wg/netstack"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func requireKey(name, value string) string {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		log.Fatalf("%s must be a 32-byte base64 WireGuard key", name)
	}
	// WireGuard's IPC interface expects hex-encoded keys (the CLI uses base64).
	return hex.EncodeToString(raw)
}

func main() {
	privateKey := requireKey("RUBEVPN_WG_PRIVATE_KEY", os.Getenv("RUBEVPN_WG_PRIVATE_KEY"))
	peerKey := requireKey("RUBEVPN_WG_PEER_PUBLIC_KEY", os.Getenv("RUBEVPN_WG_PEER_PUBLIC_KEY"))
	port := 51820
	if raw := os.Getenv("RUBEVPN_WG_LISTEN_PORT"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 65535 {
			log.Fatal("RUBEVPN_WG_LISTEN_PORT must be a valid UDP port")
		}
		port = parsed
	}

	tun, _, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1420,
	)
	if err != nil {
		log.Fatal(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	settings := fmt.Sprintf(
		"listen_port=%d\nprivate_key=%s\npublic_key=%s\nallowed_ip=10.0.0.2/32\n",
		port, privateKey, peerKey,
	)
	if err := dev.IpcSet(settings); err != nil {
		log.Fatal(err)
	}
	dev.Up()
	log.Printf("userspace WireGuard listening on UDP %d; address 10.0.0.1; peer 10.0.0.2", port)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down userspace WireGuard")
	dev.Down()
	dev.Close()
	<-dev.Wait()
}
