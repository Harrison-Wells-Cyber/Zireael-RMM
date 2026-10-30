// Package tunnel carries a standard TLS 1.3 connection inside HTTPS/WebSocket.
// Outer HTTPS may use an enterprise inspection CA. Inner TLS trusts only an
// independently provisioned deployment CA and requires individual device certificates.
package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const subprotocol = "rmm-tls-v1"
const enrollmentProtocol = "rmm-enroll-v1"
const handshakeTimeout = 10 * time.Second

type Client struct {
	inner    *tls.Config
	protocol string
}
type Server struct {
	inner    *tls.Config
	slots    chan struct{}
	protocol string
	peerMu   sync.Mutex
	peers    map[string]int
}

func roots(pem []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if len(pem) == 0 || !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("explicit deployment CA is required")
	}
	return pool, nil
}

func NewClient(identity tls.Certificate, deploymentCA []byte, serverName string) (*Client, error) {
	if len(identity.Certificate) == 0 || identity.PrivateKey == nil || serverName == "" {
		return nil, errors.New("device identity and inner server name are required")
	}
	pool, err := roots(deploymentCA)
	if err != nil {
		return nil, err
	}
	return &Client{inner: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, RootCAs: pool, ServerName: serverName, NextProtos: []string{subprotocol}}, protocol: subprotocol}, nil
}

// NewEnrollmentClient authenticates the server with the independently supplied
// deployment CA. Enrollment authorization is sent only inside this channel.
func NewEnrollmentClient(deploymentCA []byte, serverName string) (*Client, error) {
	if serverName == "" {
		return nil, errors.New("inner server name is required")
	}
	pool, err := roots(deploymentCA)
	if err != nil {
		return nil, err
	}
	return &Client{inner: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName, NextProtos: []string{enrollmentProtocol}}, protocol: enrollmentProtocol}, nil
}

type CertificateSource func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// NewEnrollmentServer exposes only a server-authenticated enrollment channel.
// Callers must validate a short-lived enrollment capability before issuing identity.
func NewEnrollmentServer(identity tls.Certificate, source CertificateSource) (*Server, error) {
	if len(identity.Certificate) == 0 || identity.PrivateKey == nil {
		return nil, errors.New("server identity required")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, SessionTicketsDisabled: true, NextProtos: []string{enrollmentProtocol}}
	if source != nil {
		config.Certificates = nil
		config.GetCertificate = source
	}
	return &Server{inner: config, slots: make(chan struct{}, 16), protocol: enrollmentProtocol, peers: map[string]int{}}, nil
}

// authorize must verify that the presented device identity is enrolled and not
// revoked. Trusting any certificate from the deployment CA alone is insufficient.
// Revocation of an active connection must also close that connection at the caller.
func NewServer(identity tls.Certificate, deviceCA []byte, authorize func(*x509.Certificate) error, source ...CertificateSource) (*Server, error) {
	if len(identity.Certificate) == 0 || identity.PrivateKey == nil || authorize == nil {
		return nil, errors.New("server identity and device authorization callback are required")
	}
	pool, err := roots(deviceCA)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true, NextProtos: []string{subprotocol}}
	if len(source) > 1 || (len(source) == 1 && source[0] == nil) {
		return nil, errors.New("invalid certificate source")
	}
	if len(source) == 1 {
		config.Certificates = nil
		config.GetCertificate = source[0]
	}
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
			return errors.New("verified device identity required")
		}
		return authorize(cs.PeerCertificates[0])
	}
	return &Server{inner: config, slots: make(chan struct{}, 16), protocol: subprotocol, peers: map[string]int{}}, nil
}

// One unauthenticated peer can occupy at most a quarter of the inner TLS
// handshake capacity. A released handshake no longer counts against this cap.
func (s *Server) reservePeer(remote string) (func(), bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	s.peerMu.Lock()
	if s.peers[host] >= 4 {
		s.peerMu.Unlock()
		return nil, false
	}
	s.peers[host]++
	s.peerMu.Unlock()
	return func() {
		s.peerMu.Lock()
		s.peers[host]--
		if s.peers[host] == 0 {
			delete(s.peers, host)
		}
		s.peerMu.Unlock()
	}, true
}

// Dial verifies outer HTTPS using OS roots unless explicit outer roots are given.
// The outer roots never affect inner server verification. No credentials or
// enrollment secrets belong in endpoint URLs or outer HTTP headers.
func (c *Client) Dial(ctx context.Context, endpoint string, outerRoots *x509.CertPool) (*tls.Conn, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, errors.New("tunnel endpoint must be an HTTPS URL without credentials, query, or fragment")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: outerRoots}
	transport.TLSHandshakeTimeout = handshakeTimeout
	transport.ResponseHeaderTimeout = handshakeTimeout
	// WebSocket upgrade needs HTTP/1.1; keep proxy compatibility predictable.
	transport.ForceAttemptHTTP2 = false
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("tunnel redirects are not allowed") }}
	deadline, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	ws, _, err := websocket.Dial(deadline, endpoint, &websocket.DialOptions{HTTPClient: httpClient, Subprotocols: []string{c.protocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return nil, fmt.Errorf("outer HTTPS connection: %w", err)
	}
	if ws.Subprotocol() != c.protocol {
		ws.CloseNow()
		return nil, errors.New("server did not negotiate the authenticated tunnel")
	}
	raw := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	ws.SetReadLimit(256 << 10)
	secured := tls.Client(raw, c.inner.Clone())
	if err = secured.HandshakeContext(deadline); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("inner server verification: %w", err)
	}
	if secured.ConnectionState().NegotiatedProtocol != c.protocol {
		ws.CloseNow()
		return nil, errors.New("inner protocol negotiation failed")
	}
	return secured, nil
}

// Accept upgrades an agent's request, then authenticates it before returning a
// usable application connection. The handler must stay alive while using it.
func (s *Server) Accept(w http.ResponseWriter, r *http.Request) (*tls.Conn, error) {
	if r.TLS == nil || r.Header.Get("Origin") != "" {
		http.Error(w, "native HTTPS agent connection required", 403)
		return nil, errors.New("invalid agent transport")
	}
	release, ok := s.reservePeer(r.RemoteAddr)
	if !ok {
		http.Error(w, "try again later", 503)
		return nil, errors.New("peer handshake capacity reached")
	}
	defer release()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "try again later", 503)
		return nil, errors.New("handshake capacity reached")
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{s.protocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return nil, err
	}
	if ws.Subprotocol() != s.protocol {
		ws.CloseNow()
		return nil, errors.New("authenticated tunnel protocol required")
	}
	raw := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	ws.SetReadLimit(256 << 10)
	secured := tls.Server(raw, s.inner.Clone())
	ctx, cancel := context.WithTimeout(r.Context(), handshakeTimeout)
	defer cancel()
	if err = secured.HandshakeContext(ctx); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("device authentication: %w", err)
	}
	if secured.ConnectionState().NegotiatedProtocol != s.protocol {
		ws.CloseNow()
		return nil, errors.New("inner protocol negotiation failed")
	}
	return secured, nil
}
