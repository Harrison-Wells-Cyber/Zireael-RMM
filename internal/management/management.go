// Package management enrolls devices and owns their authenticated live connections.
package management

import (
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/identity"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/state"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/tunnel"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
	"golang.org/x/time/rate"
)

type connection struct {
	conn    *tls.Conn
	hello   wire.Hello
	seen    time.Time
	writeMu sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
}
type DeviceView struct {
	state.Device
	Online   bool        `json:"online"`
	Details  *wire.Hello `json:"details,omitempty"`
	LastSeen *time.Time  `json:"lastSeen,omitempty"`
}

type Service struct {
	store        *state.Store
	authority    *identity.Authority
	enroll       *tunnel.Server
	control      *tunnel.Server
	limitMu      sync.Mutex
	enrollLimits map[string]*enrollLimit
	enrollOrder  *list.List
	slots        chan struct{}
	mu           sync.Mutex
	active       map[string]*connection
	closed       bool
	pending      map[string]*operation
	operations   map[*operation]struct{}
}

type enrollLimit struct {
	limiter *rate.Limiter
	element *list.Element
}

func New(store *state.Store) (*Service, error) {
	authority, err := identity.Load(store)
	if err != nil {
		return nil, err
	}
	certificate, err := authority.ServerCertificate(nil)
	if err != nil {
		return nil, err
	}
	s := &Service{store: store, authority: authority, enrollLimits: map[string]*enrollLimit{}, enrollOrder: list.New(), slots: make(chan struct{}, 128), active: map[string]*connection{}, pending: map[string]*operation{}, operations: map[*operation]struct{}{}}
	s.enroll, err = tunnel.NewEnrollmentServer(*certificate, authority.ServerCertificate)
	if err != nil {
		return nil, err
	}
	s.control, err = tunnel.NewServer(*certificate, authority.PEM, s.authorize, authority.ServerCertificate)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) CA() []byte { return append([]byte(nil), s.authority.PEM...) }

func (s *Service) authorize(cert *x509.Certificate) error {
	d, err := s.store.Device(cert.Subject.CommonName)
	if err != nil || d.Revoked != nil || d.Pending || !time.Now().Before(d.Expires) || identity.Fingerprint(cert.Raw) != d.Fingerprint {
		return state.ErrDenied
	}
	return nil
}

func (s *Service) admit(w http.ResponseWriter) bool {
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		http.Error(w, "Connection capacity reached", 503)
		return false
	}
}

func (s *Service) Enroll(w http.ResponseWriter, r *http.Request) {
	if !s.allowEnroll(r.RemoteAddr) {
		http.Error(w, "Try again shortly", 429)
		return
	}
	if !s.admit(w) {
		return
	}
	defer func() { <-s.slots }()
	conn, err := s.enroll.Accept(w, r)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var request wire.EnrollmentRequest
	if wire.Read(conn, &request) != nil {
		return
	}
	csr, keyHash, err := identity.ParseRequest(request.CSR)
	if err != nil {
		_ = wire.Write(conn, wire.EnrollmentResponse{Error: "Enrollment rejected"})
		return
	}
	d, err := s.store.EnrollFromPeer(request.Token, keyHash, request.Hostname, enrollmentPeer(r.RemoteAddr), time.Now(), func(id string) ([]byte, string, time.Time, error) { return s.authority.IssueDevice(id, csr) })
	if err != nil {
		_ = wire.Write(conn, wire.EnrollmentResponse{Error: "Enrollment rejected or expired"})
		return
	}
	_ = wire.Write(conn, wire.EnrollmentResponse{DeviceID: d.ID, Certificate: d.Certificate, Mode: d.Mode, Pending: d.Pending})
}

func (s *Service) allowEnroll(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	entry := s.enrollLimits[host]
	if entry == nil {
		if len(s.enrollLimits) >= 4096 {
			oldest := s.enrollOrder.Back()
			if oldest != nil {
				delete(s.enrollLimits, oldest.Value.(string))
				s.enrollOrder.Remove(oldest)
			}
		}
		entry = &enrollLimit{limiter: rate.NewLimiter(2, 20), element: s.enrollOrder.PushFront(host)}
		s.enrollLimits[host] = entry
	} else {
		s.enrollOrder.MoveToFront(entry.element)
	}
	return entry.limiter.Allow()
}

func validHello(h wire.Hello, d state.Device) bool {
	return h.Version == wire.Version && h.Platform == "windows" && (h.Architecture == "amd64" || h.Architecture == "arm64") && h.Mode == d.Mode && len(h.Hostname) > 0 && len(h.Hostname) <= 256 && len(h.Username) <= 256
}

func (s *Service) Connect(w http.ResponseWriter, r *http.Request) {
	if !s.admit(w) {
		return
	}
	defer func() { <-s.slots }()
	conn, err := s.control.Accept(w, r)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cert := conn.ConnectionState().PeerCertificates[0]
	id := cert.Subject.CommonName
	d, err := s.store.Device(id)
	if err != nil {
		return
	}
	var hello wire.Hello
	if wire.Read(conn, &hello) != nil || !validHello(hello, d) {
		return
	}
	sessionCtx, cancel := context.WithCancel(r.Context())
	defer cancel()
	current := &connection{conn: conn, hello: hello, seen: time.Now().UTC(), ctx: sessionCtx, cancel: cancel}
	s.mu.Lock()
	// Recheck under the same lock as revocation: it may occur after TLS verification.
	if s.closed || s.authorize(cert) != nil {
		s.mu.Unlock()
		return
	}
	if old := s.active[id]; old != nil {
		old.cancel()
		closeConn(old.conn)
	}
	if err = s.store.Record("device.connected:"+id, time.Now()); err != nil {
		s.mu.Unlock()
		return
	}
	s.active[id] = current
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.active[id] == current {
			delete(s.active, id)
		}
		_ = s.store.Record("device.disconnected:"+id, time.Now())
	}()
	if current.write(wire.Control{Type: "ready", DeviceID: id}) != nil {
		return
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		var message wire.Control
		if wire.Read(conn, &message) != nil || message.Type != "ping" || message.DeviceID != "" || message.Ticket != "" {
			return
		}
		s.mu.Lock()
		valid := s.active[id] == current && time.Now().Before(d.Expires)
		if valid {
			current.seen = time.Now().UTC()
		}
		s.mu.Unlock()
		if !valid {
			return
		}
		if current.write(wire.Control{Type: "pong"}) != nil {
			return
		}
	}
}

func closeConn(c *tls.Conn) { _ = c.SetDeadline(time.Now()); _ = c.Close() }

func (s *Service) Devices() ([]DeviceView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	devices, err := s.store.Devices()
	if err != nil {
		return nil, err
	}
	views := make([]DeviceView, 0, len(devices))
	for _, d := range devices {
		view := DeviceView{Device: d}
		if active := s.active[d.ID]; active != nil {
			hello, seen := active.hello, active.seen
			view.Online, view.Details, view.LastSeen = true, &hello, &seen
		}
		views = append(views, view)
	}
	return views, nil
}

func (s *Service) Revoke(id string) error {
	return s.RevokeAs(id, nil)
}
func (s *Service) RevokeAs(id string, actor []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.RevokeDeviceAs(id, actor, time.Now()); err != nil {
		return err
	}
	if current := s.active[id]; current != nil {
		delete(s.active, id)
		current.cancel()
		closeConn(current.conn)
	}
	return nil
}

func (s *Service) DisconnectTemporary(id string) error {
	return s.DisconnectTemporaryAs(id, nil)
}
func (s *Service) DisconnectTemporaryAs(id string, actor []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.store.Device(id)
	if err != nil {
		return err
	}
	if d.Mode != "temporary" {
		return errors.New("only temporary sessions can be ended; revoke persistent devices to remove access")
	}
	if s.active[id] == nil {
		return errors.New("device is not connected")
	}
	var recordErr error
	if actor != nil {
		recordErr = s.store.RecordActiveActor("device.session.ended:"+id, actor, time.Now())
	} else {
		recordErr = s.store.Record("device.session.ended:"+id, time.Now())
	}
	if err := recordErr; err != nil {
		return err
	}
	if current := s.active[id]; current != nil {
		delete(s.active, id)
		current.cancel()
		closeConn(current.conn)
	}
	return nil
}

func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for id, current := range s.active {
		delete(s.active, id)
		current.cancel()
		closeConn(current.conn)
	}
}

func (c *connection) write(message wire.Control) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return wire.Write(c.conn, message)
}

func enrollmentPeer(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown-peer"
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}
