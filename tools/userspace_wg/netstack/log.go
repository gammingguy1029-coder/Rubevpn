package netstack

import (
	"log"
	"os"
)

// debugf keeps per-connection chatter out of the log by default. Set
// RUBEVPN_WG_VERBOSE=1 to restore the original verbose behaviour.
func debugf(format string, args ...interface{}) {
	if os.Getenv("RUBEVPN_WG_VERBOSE") != "" {
		log.Printf(format, args...)
	}
}

// relaySlots bounds the number of concurrent TCP/UDP relay goroutines.
var relaySlots = make(chan struct{}, 512)

func acquireRelay() bool {
	select {
	case relaySlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseRelay() { <-relaySlots }
