// Experimental RubeVPN userspace WireGuard key generator.
// Emits JSON on stdout; callers must redirect to a protected file.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	"golang.org/x/crypto/curve25519"
)

func main() {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		log.Fatal(err)
	}
	// WireGuard/X25519 clamping.
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}
	output := map[string]string{
		"private_key": base64.StdEncoding.EncodeToString(private[:]),
		"public_key":  base64.StdEncoding.EncodeToString(public),
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}
