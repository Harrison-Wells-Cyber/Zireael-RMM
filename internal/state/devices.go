package state

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Device struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Mode        string     `json:"mode"`
	Certificate []byte     `json:"-"`
	Fingerprint string     `json:"fingerprint"`
	Created     time.Time  `json:"created"`
	Expires     time.Time  `json:"expires"`
	Revoked     *time.Time `json:"revoked,omitempty"`
	Pending     bool       `json:"pending,omitempty"`
}

// Keep public device JSON separate from private persistence records.
type deviceRecord struct {
	Device      Device `json:"device"`
	Certificate []byte `json:"certificate"`
	KeyHash     string `json:"keyHash,omitempty"`
}

// PublicEnrollmentToken is a stable deployment identifier, not an authorization
// capability. Devices using it remain unable to connect until an admin approves
// that specific device in the console.
func (s *Store) PublicEnrollmentToken() (string, error) {
	b, err := s.PrivateValue("public-enrollment-token", func() ([]byte, error) {
		return []byte(base64.RawURLEncoding.EncodeToString(randomBytes())), nil
	})
	return string(b), err
}

type invite struct {
	Name     string    `json:"name"`
	Mode     string    `json:"mode"`
	Actor    string    `json:"actor,omitempty"`
	Expires  time.Time `json:"expires"`
	DeviceID string    `json:"deviceID,omitempty"`
	KeyHash  string    `json:"keyHash,omitempty"`
}

func ValidMode(mode string) bool { return mode == "user" || mode == "service" || mode == "temporary" }

func randomID() string    { return hex.EncodeToString(randomBytes()) }
func randomBytes() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }
func inviteKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// PrivateValue persists secret deployment material under the database's private permissions.
// Its initializer runs once in a transaction. This is not an HTTP operation.
func (s *Store) PrivateValue(key string, init func() ([]byte, error)) ([]byte, error) {
	var result []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("private"))
		if err != nil {
			return err
		}
		if value := b.Get([]byte(key)); value != nil {
			result = append([]byte(nil), value...)
			return nil
		}
		result, err = init()
		if err != nil {
			return err
		}
		return b.Put([]byte(key), result)
	})
	return result, err
}

func (s *Store) CreateInvite(name, mode string, now time.Time) (string, time.Time, error) {
	return s.CreateInviteAs(name, mode, nil, now)
}

func (s *Store) CreateInviteAs(name, mode string, actor []byte, now time.Time) (string, time.Time, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || !ValidMode(mode) {
		return "", time.Time{}, errors.New("name and valid installation mode required")
	}
	token := base64.RawURLEncoding.EncodeToString(randomBytes())
	expires := now.Add(15 * time.Minute)
	err := s.db.Update(func(tx *bolt.Tx) error {
		if actor != nil {
			if _, e := adminFrom(tx, actor); e != nil {
				return e
			}
		}
		u, err := ownerFrom(tx)
		if err != nil {
			return err
		}
		if len(u.Credentials) == 0 {
			return ErrDenied
		}
		b, err := tx.CreateBucketIfNotExists([]byte("invites"))
		if err != nil {
			return err
		}
		c := b.Cursor()
		count := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var old invite
			if err := json.Unmarshal(v, &old); err != nil {
				return err
			}
			if !now.Before(old.Expires) {
				if err := c.Delete(); err != nil {
					return err
				}
			} else {
				count++
			}
		}
		if count >= 128 {
			return errors.New("too many unexpired enrollment links")
		}
		created := invite{Name: name, Mode: mode, Expires: expires}
		if actor != nil {
			created.Actor = adminID(actor)
		}
		if err = putJSON(b, inviteKey(token), created); err != nil {
			return err
		}
		if actor != nil {
			return auditActor(tx, "device.invite.created", adminID(actor), now)
		}
		return audit(tx, "device.invite.created", now)
	})
	return token, expires, err
}

// PendingInvite reads only installation metadata for a bearer capability.
// Viewing the instructions does not consume it; Enroll still commits it to one key.
func (s *Store) PendingInvite(token string, now time.Time) (mode string, expires time.Time, err error) {
	if len(token) != 43 {
		return "", time.Time{}, ErrDenied
	}
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("invites"))
		if b == nil {
			return ErrDenied
		}
		var in invite
		if json.Unmarshal(b.Get([]byte(inviteKey(token))), &in) != nil || !now.Before(in.Expires) || in.DeviceID != "" || !ValidMode(in.Mode) {
			return ErrDenied
		}
		mode, expires = in.Mode, in.Expires
		return nil
	})
	return
}

// Enroll commits an invite to one public key and one device. A retry with the
// same key returns the same public certificate until the invite expires. It
// cannot create another device or recover a private key.
func (s *Store) Enroll(token, keyHash string, now time.Time, issue func(string) ([]byte, string, time.Time, error)) (Device, error) {
	return s.EnrollWithName(token, keyHash, "", now, issue)
}

func (s *Store) EnrollWithName(token, keyHash, hostname string, now time.Time, issue func(string) ([]byte, string, time.Time, error)) (Device, error) {
	var result Device
	if len(token) != 43 || len(keyHash) != 64 {
		return result, ErrDenied
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		if private := tx.Bucket([]byte("private")); private != nil && subtle.ConstantTimeCompare([]byte(token), private.Get([]byte("public-enrollment-token"))) == 1 {
			return enrollPublic(tx, keyHash, hostname, now, issue, &result)
		}
		b := tx.Bucket([]byte("invites"))
		if b == nil {
			return ErrDenied
		}
		var in invite
		if json.Unmarshal(b.Get([]byte(inviteKey(token))), &in) != nil || !now.Before(in.Expires) {
			return ErrDenied
		}
		devices, err := tx.CreateBucketIfNotExists([]byte("devices"))
		if err != nil {
			return err
		}
		if in.DeviceID != "" {
			if in.KeyHash != keyHash {
				return ErrDenied
			}
			result, err = deviceFrom(devices, in.DeviceID)
			if err != nil || result.Revoked != nil || !now.Before(result.Expires) {
				return ErrDenied
			}
			return nil
		}
		if devices.Stats().KeyN >= 1024 {
			return errors.New("device limit reached")
		}
		id := randomID()
		cert, fingerprint, expires, err := issue(id)
		if err != nil {
			return err
		}
		result = Device{ID: id, Name: in.Name, Mode: in.Mode, Certificate: cert, Fingerprint: fingerprint, Created: now.UTC(), Expires: expires}
		if err = putJSON(devices, id, deviceRecord{Device: result, Certificate: cert}); err != nil {
			return err
		}
		in.DeviceID, in.KeyHash = id, keyHash
		if err = putJSON(b, inviteKey(token), in); err != nil {
			return err
		}
		return auditActor(tx, "device.enrolled:"+id, in.Actor, now)
	})
	return result, err
}

func enrollPublic(tx *bolt.Tx, keyHash, hostname string, now time.Time, issue func(string) ([]byte, string, time.Time, error), result *Device) error {
	owner, err := ownerFrom(tx)
	if err != nil || len(owner.Credentials) == 0 {
		return ErrDenied
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" || len(hostname) > 128 {
		return ErrDenied
	}
	for _, r := range hostname {
		if r < 32 || r == 127 {
			return ErrDenied
		}
	}
	devices, err := tx.CreateBucketIfNotExists([]byte("devices"))
	if err != nil {
		return err
	}
	pending := 0
	err = devices.ForEach(func(_, value []byte) error {
		var record deviceRecord
		if err := json.Unmarshal(value, &record); err != nil {
			return err
		}
		if record.KeyHash == keyHash {
			if record.Device.Revoked != nil || !now.Before(record.Device.Expires) {
				return ErrDenied
			}
			*result = record.Device
			result.Certificate = record.Certificate
		}
		if record.Device.Pending && record.Device.Revoked == nil {
			pending++
		}
		return nil
	})
	if err != nil || result.ID != "" {
		return err
	}
	if pending >= 64 || devices.Stats().KeyN >= 1024 {
		return errors.New("pending enrollment limit reached")
	}
	id := randomID()
	cert, fingerprint, expires, err := issue(id)
	if err != nil {
		return err
	}
	*result = Device{ID: id, Name: hostname, Mode: "user", Certificate: cert, Fingerprint: fingerprint, Created: now.UTC(), Expires: expires, Pending: true}
	if err := putJSON(devices, id, deviceRecord{Device: *result, Certificate: cert, KeyHash: keyHash}); err != nil {
		return err
	}
	return audit(tx, "device.pending:"+id, now)
}

func (s *Store) ApproveDeviceAs(id string, actor []byte, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if _, err := adminFrom(tx, actor); err != nil {
			return err
		}
		b := tx.Bucket([]byte("devices"))
		d, err := deviceFrom(b, id)
		if err != nil || d.Revoked != nil || !d.Pending || !now.Before(d.Expires) {
			return ErrDenied
		}
		d.Pending = false
		var record deviceRecord
		if err := json.Unmarshal(b.Get([]byte(id)), &record); err != nil {
			return err
		}
		if err := putJSON(b, id, deviceRecord{Device: d, Certificate: d.Certificate, KeyHash: record.KeyHash}); err != nil {
			return err
		}
		return auditActor(tx, "device.approved:"+id, adminID(actor), now)
	})
}

func deviceFrom(b *bolt.Bucket, id string) (Device, error) {
	var record deviceRecord
	if b == nil || b.Get([]byte(id)) == nil {
		return record.Device, ErrDenied
	}
	if err := json.Unmarshal(b.Get([]byte(id)), &record); err != nil {
		return record.Device, err
	}
	record.Device.Certificate = record.Certificate
	return record.Device, nil
}

func (s *Store) Device(id string) (d Device, err error) {
	err = s.db.View(func(tx *bolt.Tx) error { d, err = deviceFrom(tx.Bucket([]byte("devices")), id); return err })
	return
}

func (s *Store) Devices() ([]Device, error) {
	result := []Device{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("devices"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			d, err := deviceFrom(b, string(k))
			if err == nil {
				result = append(result, d)
			}
			return err
		})
	})
	return result, err
}

func (s *Store) RevokeDevice(id string, now time.Time) error {
	return s.RevokeDeviceAs(id, nil, now)
}

func (s *Store) RevokeDeviceAs(id string, actor []byte, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if actor != nil {
			if _, e := adminFrom(tx, actor); e != nil {
				return e
			}
		}
		b := tx.Bucket([]byte("devices"))
		d, err := deviceFrom(b, id)
		if err != nil {
			return err
		}
		if d.Revoked != nil {
			return nil
		}
		if d.Pending {
			if err = b.Delete([]byte(id)); err != nil {
				return err
			}
			if actor != nil {
				return auditActor(tx, "device.rejected:"+id, adminID(actor), now)
			}
			return audit(tx, "device.rejected:"+id, now)
		}
		stamp := now.UTC()
		d.Revoked = &stamp
		var record deviceRecord
		if err = json.Unmarshal(b.Get([]byte(id)), &record); err != nil {
			return err
		}
		if err = putJSON(b, id, deviceRecord{Device: d, Certificate: d.Certificate, KeyHash: record.KeyHash}); err != nil {
			return err
		}
		if actor != nil {
			return auditActor(tx, "device.revoked:"+id, adminID(actor), now)
		}
		return audit(tx, "device.revoked:"+id, now)
	})
}
