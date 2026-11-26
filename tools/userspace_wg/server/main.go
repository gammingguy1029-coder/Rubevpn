// Experimental RubeVPN userspace WireGuard server (no TUN, no admin rights).
// Keys are supplied through environment variables and are never logged.
//
// Multiple device peers are supplied as JSON in RUBEVPN_WG_PEERS_JSON:
//   [{"public_key":"<base64>","allowed_ip":"10.0.0.2/32"}]
// A status file (RUBEVPN_WG_STATUS_FILE) is refreshed with real handshake data
// so callers never have to guess which device is connected.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"rubevpn/userspace_wg/netstack"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

type peerSpec struct {
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
}

type peerStatus struct {
	PublicKey      string `json:"public_key"`
	AllowedIP      string `json:"allowed_ip,omitempty"`
	HandshakeUnix  int64  `json:"last_handshake_unix"`
	RxBytes        uint64 `json:"rx_bytes"`
	TxBytes        uint64 `json:"tx_bytes"`
}

type statusFile struct {
	UpdatedAt int64        `json:"updated_at"`
	Peers     []peerStatus `json:"peers"`
}

func requireKey(name, value string) string {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		log.Fatalf("%s must be a 32-byte base64 WireGuard key", name)
	}
	// WireGuard's IPC interface expects hex-encoded keys (the CLI uses base64).
	return hex.EncodeToString(raw)
}

func parsePeers() []peerSpec {
	raw := os.Getenv("RUBEVPN_WG_PEERS_JSON")
	var peers []peerSpec
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &peers); err != nil {
			log.Fatalf("RUBEVPN_WG_PEERS_JSON is invalid: %v", err)
		}
		for _, peer := range peers {
			requireKey("peer public_key", peer.PublicKey)
			if _, err := netip.ParsePrefix(peer.AllowedIP); err != nil {
				log.Fatalf("peer allowed_ip %q is invalid: %v", peer.AllowedIP, err)
			}
		}
		return peers
	}
	// Legacy single-peer configuration used by earlier releases.
	if legacy := os.Getenv("RUBEVPN_WG_PEER_PUBLIC_KEY"); legacy != "" {
		peers = append(peers, peerSpec{PublicKey: legacy, AllowedIP: "10.0.0.2/32"})
	}
	return peers
}

func writeStatus(path string, dev *device.Device, peers []peerSpec) {
	ipc, err := dev.IpcGet()
	if err != nil || ipc == "" {
		return
	}
	report := statusFile{UpdatedAt: time.Now().Unix(), Peers: []peerStatus{}}
	current := peerStatus{}
	havePeer := false
	allowedIPs := map[string]string{}
	for _, peer := range peers {
		hexKey := requireKey("status peer", peer.PublicKey)
		raw, _ := hex.DecodeString(hexKey)
		allowedIPs[string(raw)] = peer.AllowedIP
	}

	flush := func() {
		if !havePeer || current.PublicKey == "" {
			return
		}
		raw, err := hex.DecodeString(current.PublicKey)
		if err != nil {
			return
		}
		current.PublicKey = base64.StdEncoding.EncodeToString(raw)
		current.AllowedIP = allowedIPs[string(raw)]
		report.Peers = append(report.Peers, current)
	}

	for _, line := range strings.Split(ipc, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "public_key="):
			flush()
			current = peerStatus{PublicKey: strings.TrimPrefix(line, "public_key=")}
			havePeer = true
		case strings.HasPrefix(line, "last_handshake_time_sec=") && havePeer:
			current.HandshakeUnix, _ = strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
		case strings.HasPrefix(line, "rx_bytes=") && havePeer:
			current.RxBytes, _ = strconv.ParseUint(strings.TrimPrefix(line, "rx_bytes="), 10, 64)
		case strings.HasPrefix(line, "tx_bytes=") && havePeer:
			current.TxBytes, _ = strconv.ParseUint(strings.TrimPrefix(line, "tx_bytes="), 10, 64)
		}
	}
	flush()
	if data, err := json.Marshal(report); err == nil {
		tmp := path + ".tmp"
		if os.WriteFile(tmp, data, 0600) == nil {
			_ = os.Rename(tmp, path)
		}
	}
}

func main() {
	privateKey := requireKey("RUBEVPN_WG_PRIVATE_KEY", os.Getenv("RUBEVPN_WG_PRIVATE_KEY"))
	peers := parsePeers()
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
	settings := fmt.Sprintf("listen_port=%d\nprivate_key=%s\n", port, privateKey)
	for _, peer := range peers {
		settings += fmt.Sprintf("public_key=%s\nallowed_ip=%s\n",
			requireKey("peer public_key", peer.PublicKey), peer.AllowedIP)
	}
	// Optional verification peer used by the encrypted health check. It has a
	// distinct identity and address so it never disturbs a device session.
	if verify := os.Getenv("RUBEVPN_WG_VERIFY_PUBLIC_KEY"); verify != "" {
		settings += fmt.Sprintf("public_key=%s\nallowed_ip=10.0.0.3/32\n",
			requireKey("RUBEVPN_WG_VERIFY_PUBLIC_KEY", verify))
	}
	if err := dev.IpcSet(settings); err != nil {
		log.Fatal(err)
	}
	dev.Up()
	log.Printf("userspace WireGuard listening on UDP %d; address 10.0.0.1; %d device peer(s); mtu %d",
		port, len(peers), mtu)

	statusPath := os.Getenv("RUBEVPN_WG_STATUS_FILE")
	if statusPath != "" {
		if dir := filepath.Dir(statusPath); dir != "." {
			_ = os.MkdirAll(dir, 0700)
		}
		writeStatus(statusPath, dev, peers)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if statusPath != "" {
				writeStatus(statusPath, dev, peers)
			}
		case <-stop:
			log.Println("shutting down userspace WireGuard")
			dev.Down()
			dev.Close()
			<-dev.Wait()
			return
		}
	}
}
