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

	mtuRaw := os.Getenv("RUBEVPN_WG_MTU")
	if mtuRaw == "" {
		mtuRaw = "1420"
	}
	mtu, err := strconv.Atoi(mtuRaw)
	if err != nil || mtu < 1200 || mtu > 1500 {
		log.Fatal("RUBEVPN_WG_MTU must be an integer between 1200 and 1500")
	}

	tun, _, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		mtu,
	)
	if err != nil {
		log.Fatal(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	settings := fmt.Sprintf(
		"listen_port=%d\nprivate_key=%s\npublic_key=%s\nallowed_ip=10.0.0.2/32\n",
		port, privateKey, peerKey,
	)
	// Optional second peer used by start.bat's encrypted health check. It has
	// a different identity and address so it never disturbs the phone session.
	if verify := os.Getenv("RUBEVPN_WG_VERIFY_PUBLIC_KEY"); verify != "" {
		settings += fmt.Sprintf("public_key=%s\nallowed_ip=10.0.0.3/32\n", requireKey("RUBEVPN_WG_VERIFY_PUBLIC_KEY", verify))
	}
	if err := dev.IpcSet(settings); err != nil {
		log.Fatal(err)
	}
	dev.Up()
	log.Printf("userspace WireGuard listening on UDP %d; address 10.0.0.1; peer 10.0.0.2; mtu %d", port, mtu)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down userspace WireGuard")
	dev.Down()
	dev.Close()
	<-dev.Wait()
}
