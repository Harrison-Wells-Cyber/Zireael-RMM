package management

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
)

type operation struct {
	kind    string
	device  string
	control *connection
	ctx     context.Context
	cancel  context.CancelFunc
	ready   chan *tls.Conn
	claimed bool
	expires time.Time
}

// Operation returns a dedicated authenticated stream bound to this exact control
// connection. Revocation, reconnect, timeout, browser cancellation, and Close all
// end it. Tickets never appear in URLs or outer HTTP headers.
func (s *Service) Operation(ctx context.Context, id string, request wire.Operation) (*tls.Conn, func(), error) {
	return s.OperationAs(ctx, id, request, nil)
}

func (s *Service) OperationAs(ctx context.Context, id string, request wire.Operation, actor []byte) (*tls.Conn, func(), error) {
	if err := request.Validate(); err != nil {
		return nil, nil, err
	}
	timeout := 30 * time.Minute
	if request.Kind == "command" {
		timeout = time.Duration(request.Timeout+20) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	ticketBytes := make([]byte, 32)
	if _, err := rand.Read(ticketBytes); err != nil {
		cancel()
		return nil, nil, err
	}
	ticket := base64.RawURLEncoding.EncodeToString(ticketBytes)
	s.mu.Lock()
	current := s.active[id]
	count := 0
	desktopBusy := false
	for op := range s.operations {
		if op.device == id {
			count++
			if (request.Kind == "desktop" || request.Kind == "desktop-v2") && (op.kind == "desktop" || op.kind == "desktop-v2") {
				desktopBusy = true
			}
		}
	}
	if s.closed || current == nil || current.ctx.Err() != nil || count >= 3 || desktopBusy || len(s.operations) >= 16 {
		s.mu.Unlock()
		cancel()
		return nil, nil, errors.New("device offline or operation capacity reached")
	}
	if err := s.recordOperation("operation."+request.Kind+".started:"+id, actor, true); err != nil {
		s.mu.Unlock()
		cancel()
		return nil, nil, err
	}
	op := &operation{kind: request.Kind, device: id, control: current, ctx: ctx, cancel: cancel, ready: make(chan *tls.Conn, 1), expires: time.Now().Add(15 * time.Second)}
	s.pending[ticket] = op
	s.operations[op] = struct{}{}
	stopControl := context.AfterFunc(current.ctx, cancel)
	s.mu.Unlock()
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			cancel()
			stopControl()
			s.mu.Lock()
			delete(s.pending, ticket)
			delete(s.operations, op)
			_ = s.recordOperation("operation."+request.Kind+".ended:"+id, actor, false)
			s.mu.Unlock()
		})
	}
	if err := current.write(wire.Control{Type: "open", Ticket: ticket}); err != nil {
		cleanup()
		return nil, nil, err
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	var conn *tls.Conn
	select {
	case conn = <-op.ready:
	case <-ctx.Done():
		cleanup()
		return nil, nil, ctx.Err()
	case <-timer.C:
		cleanup()
		return nil, nil, errors.New("agent did not open operation stream")
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	closeOperation := func() { cleanup(); closeConn(conn) }
	if err := wire.Write(conn, request); err != nil {
		closeOperation()
		return nil, nil, err
	}
	return conn, closeOperation, nil
}

func (s *Service) recordOperation(action string, actor []byte, requireActive bool) error {
	if actor != nil {
		if requireActive {
			return s.store.RecordActiveActor(action, actor, time.Now())
		}
		return s.store.RecordActor(action, actor, time.Now())
	}
	return s.store.Record(action, time.Now())
}

func (s *Service) OperationStream(w http.ResponseWriter, r *http.Request) {
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
	var open wire.Open
	if wire.Read(conn, &open) != nil || len(open.Ticket) != 43 {
		return
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	s.mu.Lock()
	op := s.pending[open.Ticket]
	if op == nil || op.claimed || op.device != cert.Subject.CommonName || s.active[op.device] != op.control || op.ctx.Err() != nil || time.Now().After(op.expires) || s.authorize(cert) != nil {
		s.mu.Unlock()
		return
	}
	op.claimed = true
	delete(s.pending, open.Ticket)
	op.ready <- conn
	s.mu.Unlock()
	select {
	case <-op.ctx.Done():
	case <-r.Context().Done():
		op.cancel()
	}
	closeConn(conn)
}
