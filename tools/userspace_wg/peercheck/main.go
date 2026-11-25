// Experimental end-to-end check: a userspace WireGuard peer sends one DNS
// query through the public tunnel and reports whether a real reply came back.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type memTun struct {
	events     chan tun.Event
	toDevice   chan []byte
	fromDevice chan []byte
}

func (m *memTun) Name() (string, error)  { return "rubepeer", nil }
func (m *memTun) File() *os.File         { return nil }
func (m *memTun) Events() chan tun.Event { return m.events }
func (m *memTun) MTU() (int, error)      { return 1420, nil }
func (m *memTun) Flush() error           { return nil }
func (m *memTun) Close() error           { return nil }
func (m *memTun) Write(buf []byte, offset int) (int, error) {
	packet := append([]byte(nil), buf[offset:]...)
	select {
	case m.fromDevice <- packet:
	default:
	}
	return len(buf), nil
}
func (m *memTun) Read(buf []byte, offset int) (int, error) {
	packet := <-m.toDevice
	return copy(buf[offset:], packet), nil
}

func key(name, value string) string {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		log.Fatalf("%s must be a 32-byte base64 WireGuard key", name)
	}
	return hex.EncodeToString(raw)
}

func dnsQuery(sourceIP net.IP) []byte {
	question := layers.DNSQuestion{
		Name:  []byte("example.com"),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}
	dns := &layers.DNS{
		ID:        0x1234,
		RD:        true,
		Questions: []layers.DNSQuestion{question},
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    sourceIP,
		DstIP:    []byte{1, 1, 1, 1},
	}
	udp := &layers.UDP{SrcPort: 50000, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		log.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, udp, dns); err != nil {
		log.Fatal(err)
	}
	return buffer.Bytes()
}

func main() {
	privateKey := key("RUBEVPN_WG_PRIVATE_KEY", os.Getenv("RUBEVPN_WG_PRIVATE_KEY"))
	serverKey := key("RUBEVPN_WG_SERVER_PUBLIC_KEY", os.Getenv("RUBEVPN_WG_SERVER_PUBLIC_KEY"))
	endpoint := os.Getenv("RUBEVPN_TEST_ENDPOINT")
	if endpoint == "" {
		log.Fatal("RUBEVPN_TEST_ENDPOINT is required")
	}

	m := &memTun{
		events:     make(chan tun.Event, 4),
		toDevice:   make(chan []byte, 16),
		fromDevice: make(chan []byte, 16),
	}
	m.events <- tun.EventUp
	dev := device.NewDevice(m, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	settings := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n",
		privateKey, serverKey, endpoint,
	)
	if err := dev.IpcSet(settings); err != nil {
		log.Fatal(err)
	}
	dev.Up()

	sourceIP := net.ParseIP(os.Getenv("RUBEVPN_WG_LOCAL_ADDRESS"))
	if sourceIP == nil {
		sourceIP = net.ParseIP("10.0.0.2")
	}

	// Allow time for the handshake to complete through the relay.
	time.Sleep(2 * time.Second)
	m.toDevice <- dnsQuery(sourceIP)

	deadline := time.After(12 * time.Second)
	for {
		select {
		case packet := <-m.fromDevice:
			if len(packet) >= 20 && packet[9] == 17 { // IPv4/UDP reply
				fmt.Printf("VERIFY_OK reply_bytes=%d\n", len(packet))
				return
			}
		case <-deadline:
			fmt.Println("VERIFY_FAILED no tunneled reply received")
			return
		}
	}
}
