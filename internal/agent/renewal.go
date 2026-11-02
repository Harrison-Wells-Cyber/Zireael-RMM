package agent

import (
	"crypto/x509"
	"errors"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/state"
	"time"
)

func renewalDue(c Config, now time.Time) bool {
	pair, e := c.identity()
	if e != nil {
		return false
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	return e == nil && leaf.NotAfter.Sub(now) <= state.RenewalWindow
}
func validateReplacement(old, next Config) error {
	a, e := old.identity()
	if e != nil {
		return e
	}
	b, e := next.identity()
	if e != nil {
		return e
	}
	previous, e := x509.ParseCertificate(a.Certificate[0])
	if e != nil {
		return e
	}
	replacement, e := x509.ParseCertificate(b.Certificate[0])
	if e != nil {
		return e
	}
	if !replacement.NotAfter.After(previous.NotAfter) {
		return errors.New("replacement certificate does not extend validity")
	}
	return nil
}
