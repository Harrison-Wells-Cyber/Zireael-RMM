// Package state owns the durable application state.
package state

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/webauthn"
	bolt "go.etcd.io/bbolt"
)

var ErrDenied = errors.New("operation not authorized")

type Owner struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name,omitempty"`
	Credentials []webauthn.Credential `json:"credentials"`
	RevokedAt   *time.Time            `json:"revokedAt,omitempty"`
}

func (u Owner) WebAuthnID() []byte { return u.ID }
func (u Owner) WebAuthnName() string {
	if u.Name == "" {
		return "owner"
	}
	return u.Name
}
func (u Owner) WebAuthnDisplayName() string                { return u.WebAuthnName() }
func (u Owner) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type AdminView struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Passkeys  int        `json:"passkeys"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

type adminInvitation struct {
	Name    string    `json:"name"`
	Inviter string    `json:"inviter"`
	Expires time.Time `json:"expires"`
}

type setup struct {
	Hash    []byte    `json:"hash"`
	Expires time.Time `json:"expires"`
}

type Event struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Actor  string    `json:"actor,omitempty"`
}

type Store struct{ db *bolt.DB }

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("data directory must be accessible only to its owner (chmod 700)")
	}
	db, err := bolt.Open(filepath.Join(dir, "rmm.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("state"))
		if err != nil {
			return err
		}
		if _, err = tx.CreateBucketIfNotExists([]byte("audit")); err != nil {
			return err
		}
		if _, err = tx.CreateBucketIfNotExists([]byte("admins")); err != nil {
			return err
		}
		if _, err = tx.CreateBucketIfNotExists([]byte("admin-invitations")); err != nil {
			return err
		}
		if b.Get([]byte("owner")) == nil {
			id := make([]byte, 32)
			if _, err = rand.Read(id); err != nil {
				return err
			}
			return putJSON(b, "owner", Owner{ID: id, Name: "Owner", Credentials: []webauthn.Credential{}})
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func putJSON(b *bolt.Bucket, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}

func ownerFrom(tx *bolt.Tx) (Owner, error) {
	var u Owner
	err := json.Unmarshal(tx.Bucket([]byte("state")).Get([]byte("owner")), &u)
	return u, err
}

func (s *Store) Owner() (u Owner, err error) {
	err = s.db.View(func(tx *bolt.Tx) error { var e error; u, e = ownerFrom(tx); return e })
	return
}

func adminID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

func adminFrom(tx *bolt.Tx, id []byte) (Owner, error) {
	first, err := ownerFrom(tx)
	if err != nil {
		return Owner{}, err
	}
	if bytes.Equal(first.ID, id) {
		if first.RevokedAt != nil {
			return Owner{}, ErrDenied
		}
		return first, nil
	}
	raw := tx.Bucket([]byte("admins")).Get(id)
	if raw == nil {
		return Owner{}, ErrDenied
	}
	var admin Owner
	if err = json.Unmarshal(raw, &admin); err != nil {
		return Owner{}, err
	}
	if admin.RevokedAt != nil {
		return Owner{}, ErrDenied
	}
	return admin, nil
}

func (s *Store) Admin(id []byte) (u Owner, err error) {
	err = s.db.View(func(tx *bolt.Tx) error { var e error; u, e = adminFrom(tx, id); return e })
	return
}

func (s *Store) AdminNamed(name string) (u Owner, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		first, e := ownerFrom(tx)
		if e != nil {
			return e
		}
		if strings.EqualFold(first.WebAuthnName(), name) && first.RevokedAt == nil {
			u = first
			return nil
		}
		return tx.Bucket([]byte("admins")).ForEach(func(_, v []byte) error {
			var admin Owner
			if e := json.Unmarshal(v, &admin); e != nil {
				return e
			}
			if admin.RevokedAt == nil && strings.EqualFold(admin.Name, name) {
				u = admin
			}
			return nil
		})
	})
	if err == nil && len(u.ID) == 0 {
		err = ErrDenied
	}
	return
}

func (s *Store) Admins() (list []AdminView, err error) {
	list = []AdminView{}
	err = s.db.View(func(tx *bolt.Tx) error {
		first, e := ownerFrom(tx)
		if e != nil {
			return e
		}
		list = append(list, AdminView{ID: adminID(first.ID), Name: first.WebAuthnName(), Passkeys: len(first.Credentials), RevokedAt: first.RevokedAt})
		return tx.Bucket([]byte("admins")).ForEach(func(_, v []byte) error {
			var a Owner
			if e := json.Unmarshal(v, &a); e != nil {
				return e
			}
			list = append(list, AdminView{ID: adminID(a.ID), Name: a.Name, Passkeys: len(a.Credentials), RevokedAt: a.RevokedAt})
			return nil
		})
	})
	return
}

func validAdminName(name string) bool {
	if len(name) < 2 || len(name) > 80 || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || (unicode.IsSpace(r) && r != ' ') || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

func (s *Store) CreateAdminInvite(name string, inviter []byte, now time.Time) (string, time.Time, error) {
	if !validAdminName(name) {
		return "", time.Time{}, ErrDenied
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	hash := sha256.Sum256([]byte(token))
	expires := now.Add(15 * time.Minute)
	err := s.db.Update(func(tx *bolt.Tx) error {
		if _, e := adminFrom(tx, inviter); e != nil {
			return e
		}
		first, e := ownerFrom(tx)
		if e != nil {
			return e
		}
		if strings.EqualFold(first.WebAuthnName(), name) {
			return ErrDenied
		}
		count := 0
		if e = tx.Bucket([]byte("admins")).ForEach(func(_, v []byte) error {
			var a Owner
			if e := json.Unmarshal(v, &a); e != nil {
				return e
			}
			if a.RevokedAt == nil && strings.EqualFold(a.Name, name) {
				return ErrDenied
			}
			if a.RevokedAt == nil {
				count++
			}
			return nil
		}); e != nil {
			return e
		}
		if count >= 31 {
			return fmt.Errorf("admin limit reached")
		}
		inv := tx.Bucket([]byte("admin-invitations"))
		pending := 0
		cursor := inv.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			var existing adminInvitation
			if e = json.Unmarshal(value, &existing); e != nil {
				return e
			}
			if !now.Before(existing.Expires) {
				if e = cursor.Delete(); e != nil {
					return e
				}
				continue
			}
			if strings.EqualFold(existing.Name, name) {
				return ErrDenied
			}
			pending++
		}
		if pending >= 32 {
			return fmt.Errorf("invitation limit reached")
		}
		raw, e := json.Marshal(adminInvitation{Name: name, Inviter: adminID(inviter), Expires: expires})
		if e != nil {
			return e
		}
		if e = inv.Put(hash[:], raw); e != nil {
			return e
		}
		return auditActor(tx, "admin.invite.created", adminID(inviter), now)
	})
	return token, expires, err
}

func (s *Store) AdminInvitation(token string, now time.Time) (Owner, []byte, error) {
	hash := sha256.Sum256([]byte(token))
	var out Owner
	err := s.db.View(func(tx *bolt.Tx) error {
		var inv adminInvitation
		if json.Unmarshal(tx.Bucket([]byte("admin-invitations")).Get(hash[:]), &inv) != nil || !now.Before(inv.Expires) {
			return ErrDenied
		}
		id, e := base64.RawURLEncoding.DecodeString(inv.Inviter)
		if e != nil {
			return ErrDenied
		}
		if _, e = adminFrom(tx, id); e != nil {
			return ErrDenied
		}
		out.Name = inv.Name
		out.ID = make([]byte, 32)
		_, e = rand.Read(out.ID)
		return e
	})
	return out, hash[:], err
}

func (s *Store) RedeemAdminInvitation(hash, id []byte, credential webauthn.Credential, now time.Time) error {
	if len(hash) != sha256.Size || len(id) != 32 || !credential.Flags.UserPresent || !credential.Flags.UserVerified {
		return ErrDenied
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		var inv adminInvitation
		bucket := tx.Bucket([]byte("admin-invitations"))
		if json.Unmarshal(bucket.Get(hash), &inv) != nil || !now.Before(inv.Expires) {
			return ErrDenied
		}
		inviter, e := base64.RawURLEncoding.DecodeString(inv.Inviter)
		if e != nil {
			return ErrDenied
		}
		if _, e = adminFrom(tx, inviter); e != nil {
			return ErrDenied
		}
		first, e := ownerFrom(tx)
		if e != nil {
			return e
		}
		if bytes.Equal(first.ID, id) {
			return ErrDenied
		}
		if strings.EqualFold(first.WebAuthnName(), inv.Name) {
			return ErrDenied
		}
		for _, c := range first.Credentials {
			if bytes.Equal(c.ID, credential.ID) {
				return ErrDenied
			}
		}
		admins := tx.Bucket([]byte("admins"))
		if admins.Get(id) != nil {
			return ErrDenied
		}
		if e = admins.ForEach(func(_, v []byte) error {
			var a Owner
			if e := json.Unmarshal(v, &a); e != nil {
				return e
			}
			if a.RevokedAt == nil && strings.EqualFold(a.Name, inv.Name) {
				return ErrDenied
			}
			for _, c := range a.Credentials {
				if bytes.Equal(c.ID, credential.ID) {
					return ErrDenied
				}
			}
			return nil
		}); e != nil {
			return e
		}
		raw, e := json.Marshal(Owner{ID: id, Name: inv.Name, Credentials: []webauthn.Credential{credential}})
		if e != nil {
			return e
		}
		if e = admins.Put(id, raw); e != nil {
			return e
		}
		if e = bucket.Delete(hash); e != nil {
			return e
		}
		return auditActor(tx, "admin.created:"+adminID(id), inv.Inviter, now)
	})
}

func (s *Store) RevokeAdmin(actor, target []byte, now time.Time) error {
	if bytes.Equal(actor, target) {
		return ErrDenied
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if _, e := adminFrom(tx, actor); e != nil {
			return e
		}
		first, e := ownerFrom(tx)
		if e != nil {
			return e
		}
		// The actor is a different active account, so revoking the target
		// always leaves at least one administrator able to sign in.
		if bytes.Equal(first.ID, target) {
			if first.RevokedAt != nil {
				return ErrDenied
			}
			t := now.UTC()
			first.RevokedAt = &t
			if e = putJSON(tx.Bucket([]byte("state")), "owner", first); e != nil {
				return e
			}
			return auditActor(tx, "admin.revoked:"+adminID(target), adminID(actor), now)
		}
		admins := tx.Bucket([]byte("admins"))
		raw := admins.Get(target)
		if raw == nil {
			return ErrDenied
		}
		var admin Owner
		if e = json.Unmarshal(raw, &admin); e != nil {
			return e
		}
		if admin.RevokedAt != nil {
			return ErrDenied
		}
		t := now.UTC()
		admin.RevokedAt = &t
		raw, e = json.Marshal(admin)
		if e != nil {
			return e
		}
		if e = admins.Put(target, raw); e != nil {
			return e
		}
		return auditActor(tx, "admin.revoked:"+adminID(target), adminID(actor), now)
	})
}

// NewSetup is a local administration operation, never an HTTP endpoint.
func (s *Store) NewSetup(now time.Time) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	h := sha256.Sum256([]byte(token))
	err := s.db.Update(func(tx *bolt.Tx) error {
		u, err := ownerFrom(tx)
		if err != nil {
			return err
		}
		if len(u.Credentials) > 0 {
			return ErrDenied
		}
		if err = putJSON(tx.Bucket([]byte("state")), "setup", setup{Hash: h[:], Expires: now.Add(15 * time.Minute)}); err != nil {
			return err
		}
		return audit(tx, "setup.created", now)
	})
	return token, err
}

func checkSetup(tx *bolt.Tx, hash []byte, now time.Time) bool {
	var v setup
	if json.Unmarshal(tx.Bucket([]byte("state")).Get([]byte("setup")), &v) != nil {
		return false
	}
	return now.Before(v.Expires) && len(hash) == sha256.Size && subtle.ConstantTimeCompare(v.Hash, hash) == 1
}

// AuthorizeSetup returns a generation identifier, never the raw bootstrap token.
func (s *Store) AuthorizeSetup(token string, now time.Time) ([]byte, error) {
	h := sha256.Sum256([]byte(token))
	err := s.db.View(func(tx *bolt.Tx) error {
		u, e := ownerFrom(tx)
		if e != nil {
			return e
		}
		if len(u.Credentials) != 0 || !checkSetup(tx, h[:], now) {
			return ErrDenied
		}
		return nil
	})
	return h[:], err
}

// AddCredential commits the first owner and consumes bootstrap in the same transaction.
// A nil setupHash is allowed only by the caller's freshly authenticated owner flow.
func (s *Store) AddCredential(c webauthn.Credential, setupHash []byte, now time.Time) error {
	if !c.Flags.UserPresent || !c.Flags.UserVerified {
		return ErrDenied
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		u, err := ownerFrom(tx)
		if err != nil {
			return err
		}
		if len(u.Credentials) == 0 {
			if !checkSetup(tx, setupHash, now) {
				return ErrDenied
			}
		} else if setupHash != nil {
			return ErrDenied
		}
		if len(u.Credentials) >= 10 {
			return errors.New("credential limit reached")
		}
		for _, existing := range u.Credentials {
			if bytes.Equal(existing.ID, c.ID) {
				return ErrDenied
			}
		}
		u.Credentials = append(u.Credentials, c)
		b := tx.Bucket([]byte("state"))
		if err = putJSON(b, "owner", u); err != nil {
			return err
		}
		if err = b.Delete([]byte("setup")); err != nil {
			return err
		}
		return auditActor(tx, "passkey.added", adminID(u.ID), now)
	})
}

func (s *Store) AddAdminCredential(id []byte, c webauthn.Credential, now time.Time) error {
	if !c.Flags.UserPresent || !c.Flags.UserVerified {
		return ErrDenied
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		a, e := adminFrom(tx, id)
		if e != nil {
			return e
		}
		if len(a.Credentials) >= 10 {
			return errors.New("credential limit reached")
		}
		first, e := ownerFrom(tx)
		if e != nil {
			return e
		}
		for _, old := range first.Credentials {
			if bytes.Equal(old.ID, c.ID) {
				return ErrDenied
			}
		}
		admins := tx.Bucket([]byte("admins"))
		if e = admins.ForEach(func(_, v []byte) error {
			var other Owner
			if e := json.Unmarshal(v, &other); e != nil {
				return e
			}
			for _, old := range other.Credentials {
				if bytes.Equal(old.ID, c.ID) {
					return ErrDenied
				}
			}
			return nil
		}); e != nil {
			return e
		}
		a.Credentials = append(a.Credentials, c)
		if bytes.Equal(first.ID, id) {
			e = putJSON(tx.Bucket([]byte("state")), "owner", a)
		} else {
			var raw []byte
			raw, e = json.Marshal(a)
			if e == nil {
				e = admins.Put(id, raw)
			}
		}
		if e != nil {
			return e
		}
		return auditActor(tx, "passkey.added", adminID(id), now)
	})
}

func (s *Store) UpdateCredential(c webauthn.Credential, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		u, err := ownerFrom(tx)
		if err != nil {
			return err
		}
		for i, old := range u.Credentials {
			if !bytes.Equal(old.ID, c.ID) {
				continue
			}
			// Do not lose a newer nonzero counter to concurrent assertions.
			if old.Authenticator.SignCount != 0 && c.Authenticator.SignCount <= old.Authenticator.SignCount {
				return ErrDenied
			}
			u.Credentials[i] = c
			if err = putJSON(tx.Bucket([]byte("state")), "owner", u); err != nil {
				return err
			}
			return audit(tx, "auth.login", now)
		}
		return ErrDenied
	})
}

func (s *Store) UpdateAdminCredential(id []byte, c webauthn.Credential, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		a, e := adminFrom(tx, id)
		if e != nil {
			return e
		}
		for i, old := range a.Credentials {
			if !bytes.Equal(old.ID, c.ID) {
				continue
			}
			if old.Authenticator.SignCount != 0 && c.Authenticator.SignCount <= old.Authenticator.SignCount {
				return ErrDenied
			}
			a.Credentials[i] = c
			first, e := ownerFrom(tx)
			if e != nil {
				return e
			}
			if bytes.Equal(first.ID, id) {
				e = putJSON(tx.Bucket([]byte("state")), "owner", a)
			} else {
				var raw []byte
				raw, e = json.Marshal(a)
				if e == nil {
					e = tx.Bucket([]byte("admins")).Put(id, raw)
				}
			}
			if e != nil {
				return e
			}
			return auditActor(tx, "auth.login", adminID(id), now)
		}
		return ErrDenied
	})
}

func audit(tx *bolt.Tx, action string, now time.Time) error { return auditActor(tx, action, "", now) }
func auditActor(tx *bolt.Tx, action, actor string, now time.Time) error {
	b := tx.Bucket([]byte("audit"))
	seq, err := b.NextSequence()
	if err != nil {
		return err
	}
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], seq)
	raw, err := json.Marshal(Event{Time: now.UTC(), Action: action, Actor: actor})
	if err != nil {
		return err
	}
	return b.Put(key[:], raw)
}

func (s *Store) Record(action string, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error { return audit(tx, action, now) })
}

func (s *Store) RecordActor(action string, actor []byte, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return auditActor(tx, action, adminID(actor), now)
	})
}

func (s *Store) RecordActiveActor(action string, actor []byte, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if _, e := adminFrom(tx, actor); e != nil {
			return e
		}
		return auditActor(tx, action, adminID(actor), now)
	})
}

func (s *Store) Events() (events []Event, err error) {
	events = []Event{}
	err = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte("audit")).Cursor()
		for k, v := c.Last(); k != nil && len(events) < 100; k, v = c.Prev() {
			var event Event
			if e := json.Unmarshal(v, &event); e != nil {
				return e
			}
			events = append(events, event)
		}
		return nil
	})
	return
}
