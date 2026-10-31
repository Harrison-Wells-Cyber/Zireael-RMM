// Package console serves the passkey-protected operator console.
package console

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/bootstrap"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/management"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/state"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/weborigin"
	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/time/rate"
)

//go:embed web/*
var assets embed.FS

type ceremony struct {
	Kind       string
	Data       webauthn.SessionData
	SetupHash  []byte
	AdminID    []byte
	AdminName  string
	InviteHash []byte
	Expires    time.Time
}

type clientLimit struct {
	auth, help *rate.Limiter
	element    *list.Element
}

type Console struct {
	store         *state.Store
	wa            *webauthn.WebAuthn
	sessions      *scs.SessionManager
	origin        string
	host          string
	mu            sync.Mutex
	pending       map[string]ceremony
	limits        map[string]*clientLimit
	limitOrder    *list.List
	agents        *management.Service
	artifact      *bootstrap.Artifact
	publicOnce    sync.Once
	publicCommand string
	publicPackage *bootstrap.Package
	publicErr     error
}

// WithAgents is called during startup before serving requests.
func (c *Console) WithAgents(service *management.Service, artifact *bootstrap.Artifact) {
	c.agents, c.artifact = service, artifact
}

func New(store *state.Store, origin string) (*Console, error) {
	u, err := weborigin.Parse(origin)
	if err != nil {
		return nil, err
	}
	origin = u.String()
	wa, err := webauthn.New(&webauthn.Config{
		RPID: u.Hostname(), RPDisplayName: "Zireael-RMM", RPOrigins: []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired},
		AttestationPreference:  protocol.PreferNoAttestation,
		Timeouts:               webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute}, Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute}},
	})
	if err != nil {
		return nil, err
	}
	sm := scs.New()
	sm.Cookie.Name = "__Host-zireael-rmm"
	sm.Cookie.Secure = true
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteStrictMode
	sm.Cookie.Persist = false
	sm.HashTokenInStore = true
	sm.Lifetime = 8 * time.Hour
	sm.IdleTimeout = 20 * time.Minute
	sm.Store = newSessions(sm.Store.(*memstore.MemStore), sm.Lifetime)
	sm.ErrorFunc = func(w http.ResponseWriter, r *http.Request, err error) {
		// A failed commit can replace a prepared file/stream response. Its size
		// and download headers must not describe the JSON error we send instead.
		w.Header().Del("Content-Length")
		w.Header().Del("Content-Disposition")
		w.Header().Del("Content-Encoding")
		if errors.Is(err, errSessionEnded) {
			fail(w, http.StatusUnauthorized, "Session ended; sign in again")
			return
		}
		slog.Error("session failure", "error", err)
		fail(w, http.StatusInternalServerError, "Session unavailable")
	}
	return &Console{store: store, wa: wa, sessions: sm, origin: origin, host: u.Host, pending: map[string]ceremony{}, limits: map[string]*clientLimit{}, limitOrder: list.New()}, nil
}

// The TCP peer, rather than an untrusted forwarding header, defines a quota.
// A deployment behind a reverse proxy should enforce per-client limits there.
func (c *Console) allowClient(r *http.Request, auth bool) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.limits[host]
	if entry == nil {
		if len(c.limits) >= 4096 {
			oldest := c.limitOrder.Back()
			if oldest != nil {
				delete(c.limits, oldest.Value.(string))
				c.limitOrder.Remove(oldest)
			}
		}
		entry = &clientLimit{auth: rate.NewLimiter(2, 20), help: rate.NewLimiter(5, 20), element: c.limitOrder.PushFront(host)}
		c.limits[host] = entry
	} else if entry.element != nil {
		c.limitOrder.MoveToFront(entry.element)
	} else {
		entry.element = c.limitOrder.PushFront(host)
	}
	if auth {
		return entry.auth.Allow()
	}
	return entry.help.Allow()
}

func (c *Console) Close() {
	if s, ok := c.sessions.Store.(*retiredSessions); ok {
		s.Close()
	}
}

func (c *Console) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /admin", c.page)
	m.HandleFunc("GET /admin/desktop", c.desktopPage)
	m.HandleFunc("GET /assets/{name}", c.asset)
	m.HandleFunc("POST /api/auth/register/begin", c.beginRegister)
	m.HandleFunc("POST /api/auth/register/finish", c.finishRegister)
	m.HandleFunc("POST /api/auth/login/begin", c.beginLogin)
	m.HandleFunc("POST /api/auth/login/finish", c.finishLogin)
	m.HandleFunc("GET /api/session", c.session)
	m.HandleFunc("POST /api/logout", c.requireOwner(c.logout))
	m.HandleFunc("GET /api/status", c.requireOwner(c.status))
	m.HandleFunc("GET /api/audit", c.requireOwner(c.audit))
	m.HandleFunc("GET /api/admins", c.requireOwner(c.admins))
	m.HandleFunc("POST /api/admins/invites", c.requireOwner(c.adminInvite))
	m.HandleFunc("POST /api/admins/{id}/revoke", c.requireOwner(c.adminRevoke))
	if c.agents != nil {
		m.HandleFunc("GET /api/devices", c.requireOwner(c.devices))
		m.HandleFunc("GET /api/devices/{id}/desktop-v2", c.requireOwner(c.desktop))
		m.HandleFunc("POST /api/devices/{id}/command", c.requireOwner(c.command))
		m.HandleFunc("POST /api/devices/{id}/upload", c.requireOwner(c.upload))
		m.HandleFunc("POST /api/devices/{id}/download", c.requireOwner(c.download))
		m.HandleFunc("POST /api/invites", c.requireOwner(c.invite))
		m.HandleFunc("POST /api/devices/{id}/revoke", c.requireOwner(c.revoke))
		m.HandleFunc("POST /api/devices/{id}/approve", c.requireOwner(c.approve))
		m.HandleFunc("POST /api/devices/{id}/disconnect", c.requireOwner(c.disconnect))
	}
	root := http.NewServeMux()
	root.HandleFunc("GET /{$}", c.helpPage)
	root.Handle("/", c.sessions.LoadAndSave(m))
	if c.agents != nil {
		root.HandleFunc("GET /agent/v1/enroll", c.agents.Enroll)
		root.HandleFunc("GET /agent/v1/connect", c.agents.Connect)
		root.HandleFunc("GET /agent/v1/operation", c.agents.OperationStream)
		if c.artifact != nil {
			root.HandleFunc("GET /agent/download", c.artifact.Download)
			root.HandleFunc("GET /agent.ps1", c.powerShellPackage)
			root.HandleFunc("GET /agent", c.powerShellPackage)
			root.HandleFunc("GET /api/default-command", c.defaultCommand)
			root.HandleFunc("POST /api/support-invite", c.supportInvite)
		}
	}
	return c.security(root)
}

func (c *Console) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data: blob:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		if !strings.EqualFold(r.Host, c.host) {
			fail(w, 421, "Unexpected host")
			return
		}
		// Public instructions and a private admin invitation may be opened
		// from email or a messaging site. Neither GET page performs an action.
		publicPage := (r.Method == "GET" || r.Method == "HEAD") && (r.URL.Path == "/" || (r.URL.Path == "/admin" && r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"))
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" && !publicPage {
			fail(w, 403, "Cross-site request rejected")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Origin") != c.origin || r.Header.Get("X-RMM-Request") != "1" {
				fail(w, 403, "Request origin rejected")
				return
			}
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			upload := r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.HasSuffix(r.URL.Path, "/upload")
			if err != nil || (!upload && media != "application/json") || (upload && media != "application/octet-stream") {
				fail(w, 415, "JSON required")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/auth/") && !c.allowClient(r, true) {
			w.Header().Set("Retry-After", "1")
			fail(w, 429, "Too many authentication attempts; try again shortly")
			return
		}
		limit := int64(64 << 10)
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.HasSuffix(r.URL.Path, "/upload") {
			limit = 1 << 30
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func (c *Console) adminID(r *http.Request) []byte {
	id, err := base64.RawURLEncoding.DecodeString(c.sessions.GetString(r.Context(), "adminID"))
	if err != nil || len(id) != 32 {
		return nil
	}
	return id
}
func (c *Console) owner(r *http.Request) bool {
	if !c.sessions.GetBool(r.Context(), "owner") {
		return false
	}
	id := c.adminID(r)
	if id == nil {
		return false
	}
	_, err := c.store.Admin(id)
	return err == nil
}
func (c *Console) fresh(r *http.Request) bool {
	age := time.Since(time.Unix(c.sessions.GetInt64(r.Context(), "authenticated"), 0))
	return c.owner(r) && age >= 0 && age < 5*time.Minute
}
func (c *Console) requireOwner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !c.owner(r) {
			fail(w, 401, "Passkey sign-in required")
			return
		}
		next(w, r)
	}
}

func (c *Console) remember(r *http.Request, p ceremony) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	id := base64.RawURLEncoding.EncodeToString(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, old := range c.pending {
		if time.Now().After(old.Expires) {
			delete(c.pending, k)
		}
	}
	delete(c.pending, c.sessions.GetString(r.Context(), "ceremony"))
	if len(c.pending) >= 1024 {
		return errors.New("too many pending ceremonies")
	}
	p.Expires = time.Now().Add(5 * time.Minute)
	c.pending[id] = p
	c.sessions.Put(r.Context(), "ceremony", id)
	return nil
}

// take atomically consumes a challenge even if the assertion subsequently fails.
func (c *Console) take(r *http.Request, kind string) (ceremony, bool) {
	id := c.sessions.GetString(r.Context(), "ceremony")
	c.sessions.Remove(r.Context(), "ceremony")
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[id]
	delete(c.pending, id)
	return p, ok && p.Kind == kind && time.Now().Before(p.Expires)
}

func (c *Console) beginRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SetupToken  string `json:"setupToken"`
		AdminInvite string `json:"adminInvite"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "Invalid registration request")
		return
	}
	first, err := c.store.Owner()
	if err != nil {
		fail(w, 500, "Storage unavailable")
		return
	}
	var u state.Owner
	var hash, inviteHash []byte
	if len(first.Credentials) == 0 {
		if in.AdminInvite != "" {
			fail(w, 403, "Complete local setup first")
			return
		}
		hash, err = c.store.AuthorizeSetup(in.SetupToken, time.Now())
		u = first
		if err != nil {
			fail(w, 403, "Setup authorization rejected or expired")
			return
		}
	} else if in.AdminInvite != "" {
		if in.SetupToken != "" {
			fail(w, 400, "Choose one registration method")
			return
		}
		u, inviteHash, err = c.store.AdminInvitation(in.AdminInvite, time.Now())
		if err != nil {
			fail(w, 403, "Admin invitation rejected or expired")
			return
		}
	} else {
		if !c.fresh(r) {
			fail(w, 401, "Sign in again before adding a passkey")
			return
		}
		u, err = c.store.Admin(c.adminID(r))
		if err != nil {
			fail(w, 401, "Sign in again")
			return
		}
	}
	opts, data, err := c.wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.Credentials).CredentialDescriptors()))
	if err != nil {
		fail(w, 500, "Unable to start registration")
		return
	}
	if err = c.remember(r, ceremony{Kind: "register", Data: *data, SetupHash: hash, AdminID: u.ID, InviteHash: inviteHash, AdminName: u.WebAuthnName()}); err != nil {
		fail(w, 503, "Try again shortly")
		return
	}
	reply(w, 200, opts)
}

func (c *Console) finishRegister(w http.ResponseWriter, r *http.Request) {
	p, ok := c.take(r, "register")
	if !ok {
		fail(w, 400, "Registration expired or already used")
		return
	}
	if p.SetupHash == nil && p.InviteHash == nil && (!c.fresh(r) || !bytes.Equal(p.AdminID, c.adminID(r))) {
		fail(w, 401, "Sign in again before adding a passkey")
		return
	}
	u := state.Owner{ID: p.AdminID, Name: p.AdminName}
	if p.InviteHash == nil {
		var err error
		u, err = c.store.Admin(p.AdminID)
		if err != nil {
			fail(w, 403, "Registration no longer authorized")
			return
		}
	}
	credential, err := c.wa.FinishRegistration(u, p.Data, r)
	if err != nil || credential == nil || !credential.Flags.UserVerified || !credential.Flags.UserPresent {
		fail(w, 403, "Passkey verification failed")
		return
	}
	if p.InviteHash != nil {
		err = c.store.RedeemAdminInvitation(p.InviteHash, p.AdminID, *credential, time.Now())
	} else if p.SetupHash != nil {
		err = c.store.AddCredential(*credential, p.SetupHash, time.Now())
	} else {
		err = c.store.AddAdminCredential(p.AdminID, *credential, time.Now())
	}
	if err != nil {
		fail(w, 403, "Registration no longer authorized")
		return
	}
	if err = c.authenticate(r, p.AdminID); err != nil {
		fail(w, 500, "Unable to establish session")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func (c *Console) beginLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "Invalid sign-in request")
		return
	}
	if input.Name == "" {
		input.Name = "Owner"
	}
	u, err := c.store.AdminNamed(input.Name)
	if err != nil {
		fail(w, 403, "Passkey sign-in unavailable")
		return
	}
	if len(u.Credentials) == 0 {
		fail(w, 403, "Complete local setup first")
		return
	}
	opts, data, err := c.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		fail(w, 500, "Unable to start sign-in")
		return
	}
	if err = c.remember(r, ceremony{Kind: "login", Data: *data, AdminID: u.ID}); err != nil {
		fail(w, 503, "Try again shortly")
		return
	}
	reply(w, 200, opts)
}

func (c *Console) finishLogin(w http.ResponseWriter, r *http.Request) {
	p, ok := c.take(r, "login")
	if !ok {
		fail(w, 400, "Sign-in expired or already used")
		return
	}
	u, err := c.store.Admin(p.AdminID)
	if err != nil {
		fail(w, 403, "Passkey sign-in unavailable")
		return
	}
	credential, err := c.wa.FinishLogin(u, p.Data, r)
	if err != nil || credential == nil || !credential.Flags.UserVerified || !credential.Flags.UserPresent || credential.Authenticator.CloneWarning {
		fail(w, 403, "Passkey verification failed")
		return
	}
	if err = c.store.UpdateAdminCredential(p.AdminID, *credential, time.Now()); err != nil {
		fail(w, 403, "Credential state changed; sign in again")
		return
	}
	if err = c.authenticate(r, p.AdminID); err != nil {
		fail(w, 500, "Unable to establish session")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func (c *Console) authenticate(r *http.Request, id []byte) error {
	if err := c.sessions.RenewToken(r.Context()); err != nil {
		return err
	}
	c.sessions.Put(r.Context(), "owner", true)
	c.sessions.Put(r.Context(), "adminID", adminIDString(id))
	c.sessions.Put(r.Context(), "authenticated", time.Now().Unix())
	return nil
}

func adminIDString(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

func (c *Console) session(w http.ResponseWriter, r *http.Request) {
	u, err := c.store.Owner()
	if err != nil {
		fail(w, 500, "Storage unavailable")
		return
	}
	name := ""
	if c.owner(r) {
		if a, e := c.store.Admin(c.adminID(r)); e == nil {
			name = a.WebAuthnName()
		}
	}
	reply(w, 200, map[string]any{"authenticated": c.owner(r), "setupRequired": len(u.Credentials) == 0, "adminName": name, "adminID": adminIDString(c.adminID(r))})
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	id := c.adminID(r)
	c.take(r, "")
	if err := c.sessions.Destroy(r.Context()); err != nil {
		fail(w, 500, "Unable to end session")
		return
	}
	if err := c.store.RecordActor("auth.logout", id, time.Now()); err != nil {
		slog.Error("audit write failed", "error", err)
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func (c *Console) status(w http.ResponseWriter, r *http.Request) {
	u, err := c.store.Admin(c.adminID(r))
	if err != nil {
		fail(w, 500, "Storage unavailable")
		return
	}
	architecture := ""
	if c.artifact != nil {
		architecture = c.artifact.Architecture
	}
	reply(w, 200, map[string]any{"passkeys": len(u.Credentials), "stage": "Support preview", "agentsEnabled": c.agents != nil, "agentPackageAvailable": c.artifact != nil, "agentArchitecture": architecture, "adminName": u.WebAuthnName()})
}

func (c *Console) audit(w http.ResponseWriter, r *http.Request) {
	events, err := c.store.Events()
	if err != nil {
		fail(w, 500, "Audit unavailable")
		return
	}
	reply(w, 200, events)
}

func (c *Console) page(w http.ResponseWriter, r *http.Request) {
	raw, _ := assets.ReadFile("web/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(raw)
}
func (c *Console) helpPage(w http.ResponseWriter, r *http.Request) {
	raw, _ := assets.ReadFile("web/help.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(raw)
}
func (c *Console) asset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var contentType string
	switch name {
	case "app.js", "support.js", "desktop-viewer.js", "desktop-page.js", "help.js":
		contentType = "text/javascript; charset=utf-8"
	case "app.css", "help.css", "theme.css":
		contentType = "text/css; charset=utf-8"
	case "swallow.png":
		contentType = "image/png"
	default:
		http.NotFound(w, r)
		return
	}
	raw, err := assets.ReadFile("web/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(raw)
}
