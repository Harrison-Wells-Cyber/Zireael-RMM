package console

import (
	"errors"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2/memstore"
)

var errSessionEnded = errors.New("session was ended, expired, or replaced")

// retiredSessions prevents an in-flight request from restoring a session after
// logout or rotation. SCS still generates, encodes, and validates session tokens.
// Its backing store is extended with tombstones because ordinary Delete/Commit
// alone permit a late Commit from a previously loaded request to revive a token.
type retiredSessions struct {
	mu       sync.Mutex
	backing  *memstore.MemStore
	retired  map[string]time.Time
	expires  map[string]time.Time
	lifetime time.Duration
}

func newSessions(backing *memstore.MemStore, lifetime time.Duration) *retiredSessions {
	return &retiredSessions{backing: backing, retired: map[string]time.Time{}, expires: map[string]time.Time{}, lifetime: lifetime}
}

func (s *retiredSessions) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, expires := range s.retired {
		if now.After(expires) {
			delete(s.retired, key)
		}
	}
	delete(s.expires, token)
	s.retired[token] = now.Add(s.lifetime)
	return s.backing.Delete(token)
}

func (s *retiredSessions) Find(token string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.retired[token]; ok {
		return nil, false, nil
	}
	return s.backing.Find(token)
}

func (s *retiredSessions) Commit(token string, data []byte, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, expiry := range s.expires {
		if !now.Before(expiry) {
			delete(s.expires, key)
			s.retired[key] = now.Add(s.lifetime)
		}
	}
	for key, expiry := range s.retired {
		if !now.Before(expiry) {
			delete(s.retired, key)
		}
	}
	if _, ok := s.retired[token]; ok {
		return errSessionEnded
	}
	if !now.Before(expires) {
		return errSessionEnded
	}
	if err := s.backing.Commit(token, data, expires); err != nil {
		return err
	}
	s.expires[token] = expires
	return nil
}

func (s *retiredSessions) Close() { s.backing.StopCleanup() }
