package state

import (
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

const RenewalWindow = 90 * 24 * time.Hour

type renewalRecord struct {
	Certificate []byte    `json:"certificate"`
	Fingerprint string    `json:"fingerprint"`
	Expires     time.Time `json:"expires"`
}

func certificateAllowed(r deviceRecord, fp string, now time.Time) bool {
	if r.Device.Pending || r.Device.Revoked != nil {
		return false
	}
	return r.Device.Fingerprint == fp && now.Before(r.Device.Expires) || r.Renewal != nil && r.Renewal.Fingerprint == fp && now.Before(r.Renewal.Expires)
}
func readDeviceRecord(tx *bolt.Tx, id string) (deviceRecord, error) {
	var r deviceRecord
	b := tx.Bucket([]byte("devices"))
	if b == nil {
		return r, ErrDenied
	}
	raw := b.Get([]byte(id))
	if raw == nil {
		return r, ErrDenied
	}
	e := json.Unmarshal(raw, &r)
	return r, e
}
func (s *Store) AuthorizeCertificate(id, fp string, now time.Time) error {
	return s.db.View(func(tx *bolt.Tx) error {
		r, e := readDeviceRecord(tx, id)
		if e != nil {
			return e
		}
		if !certificateAllowed(r, fp, now) {
			return ErrDenied
		}
		return nil
	})
}

// PrepareRenewal keeps the old certificate active until the replacement has
// authenticated a new control connection. Retries return the same certificate.
func (s *Store) PrepareRenewal(id, fp string, now time.Time, issue func() ([]byte, string, time.Time, error)) ([]byte, error) {
	var cert []byte
	e := s.db.Update(func(tx *bolt.Tx) error {
		r, e := readDeviceRecord(tx, id)
		if e != nil || !certificateAllowed(r, fp, now) || r.Device.Fingerprint != fp {
			return ErrDenied
		}
		if r.Device.Expires.Sub(now) > RenewalWindow {
			return errors.New("certificate is not due for renewal")
		}
		if r.Renewal != nil && now.Before(r.Renewal.Expires) {
			cert = append([]byte(nil), r.Renewal.Certificate...)
			return nil
		}
		replacement, nextFingerprint, expiry, e := issue()
		if e != nil {
			return e
		}
		if len(replacement) == 0 || len(nextFingerprint) != 64 || !expiry.After(r.Device.Expires) {
			return errors.New("replacement certificate must extend validity")
		}
		r.Renewal = &renewalRecord{Certificate: replacement, Fingerprint: nextFingerprint, Expires: expiry}
		if e = putJSON(tx.Bucket([]byte("devices")), id, r); e != nil {
			return e
		}
		cert = append([]byte(nil), replacement...)
		return nil
	})
	return cert, e
}

// AcceptDeviceConnection promotes a staged certificate only after TLS and the
// hello have succeeded, and preserves the last reported build while offline.
func (s *Store) AcceptDeviceConnection(id, fp, build, digest, arch string, now time.Time) (Device, error) {
	var d Device
	e := s.db.Update(func(tx *bolt.Tx) error {
		r, e := readDeviceRecord(tx, id)
		if e != nil || !certificateAllowed(r, fp, now) {
			return ErrDenied
		}
		if r.Renewal != nil && r.Renewal.Fingerprint == fp {
			r.Certificate = r.Renewal.Certificate
			r.Device.Fingerprint = r.Renewal.Fingerprint
			r.Device.Expires = r.Renewal.Expires
			r.Renewal = nil
			if e = audit(tx, "device.certificate.renewed:"+id, now); e != nil {
				return e
			}
		}
		r.Device.AgentVersion, r.Device.AgentSHA256, r.Device.Architecture = build, digest, arch
		if e = putJSON(tx.Bucket([]byte("devices")), id, r); e != nil {
			return e
		}
		d = r.Device
		d.Certificate = append([]byte(nil), r.Certificate...)
		return nil
	})
	return d, e
}
