package handler

import (
	"log"
	"os"
)

// debugf gates ICMP chatter behind RUBEVPN_WG_VERBOSE.
func debugf(format string, args ...interface{}) {
	if os.Getenv("RUBEVPN_WG_VERBOSE") != "" {
		log.Printf(format, args...)
	}
}
