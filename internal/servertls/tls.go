// Package servertls selects automatic ACME or externally managed PEM certificates.
package servertls

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/weborigin"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Options struct {
	Domain, Origin, Listen, DataDir string
	CertFile, KeyFile               string
	Email, DirectoryURL             string
}
type Setup struct {
	Origin    string
	TLS       *tls.Config
	Challenge http.Handler
	Automatic bool
	Cached    bool
	Warm      func() error
}

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func Configure(o Options) (*Setup, error) {
	o.Domain = strings.ToLower(o.Domain)
	if o.Domain != "" && (len(o.Domain) > 253 || !domainPattern.MatchString(o.Domain) || net.ParseIP(o.Domain) != nil) {
		return nil, errors.New("domain must be a DNS name without a scheme, port, wildcard, or trailing dot")
	}
	if o.Origin == "" {
		if o.Domain == "" {
			return nil, errors.New("provide --domain for automatic certificates, or --origin and PEM certificate files")
		}
		_, port, err := net.SplitHostPort(o.Listen)
		if err != nil {
			return nil, err
		}
		o.Origin = "https://" + o.Domain
		if port != "443" {
			o.Origin += ":" + port
		}
	}
	u, err := weborigin.Parse(o.Origin)
	if err != nil {
		return nil, err
	}
	o.Origin = u.String()
	if o.Domain != "" && !strings.EqualFold(o.Domain, u.Hostname()) {
		return nil, errors.New("domain must match the public origin hostname")
	}
	result := &Setup{Origin: o.Origin}
	if o.CertFile != "" || o.KeyFile != "" {
		if o.CertFile == "" || o.KeyFile == "" {
			return nil, errors.New("both --tls-cert and --tls-key are required")
		}
		if o.DirectoryURL != "" || o.Email != "" {
			return nil, errors.New("ACME options cannot be combined with supplied certificate files")
		}
		load := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello != nil && hello.ServerName != "" && !strings.EqualFold(hello.ServerName, u.Hostname()) {
				return nil, errors.New("unexpected TLS server name")
			}
			pair, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
			if err != nil {
				return nil, err
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				return nil, err
			}
			if err = leaf.VerifyHostname(u.Hostname()); err != nil {
				return nil, err
			}
			if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
				return nil, errors.New("supplied certificate is not currently valid")
			}
			return &pair, nil
		}
		if _, err := load(nil); err != nil {
			return nil, err
		}
		// Reload on each handshake to support Certbot, private CAs and other managers.
		result.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: load}
		return result, nil
	}
	if o.Domain == "" {
		return nil, errors.New("automatic certificates require --domain")
	}
	if o.DirectoryURL != "" {
		directory, err := url.Parse(o.DirectoryURL)
		if err != nil || directory.Scheme != "https" || directory.Host == "" || directory.User != nil || directory.Fragment != "" {
			return nil, errors.New("ACME directory must be an HTTPS URL")
		}
	}
	cacheDir := filepath.Join(o.DataDir, "acme")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(cacheDir)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("ACME cache directory must have mode 0700")
	}
	manager := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(o.Domain), Cache: autocert.DirCache(cacheDir), Email: o.Email}
	result.Cached = cachedCertificate(cacheDir, o.Domain)
	if o.DirectoryURL != "" {
		manager.Client = &acme.Client{DirectoryURL: o.DirectoryURL}
	}
	result.Automatic = true
	result.TLS = manager.TLSConfig()
	result.TLS.MinVersion = tls.VersionTLS12
	result.TLS.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !strings.EqualFold(hello.ServerName, o.Domain) {
			return nil, errors.New("unexpected TLS server name")
		}
		return manager.GetCertificate(hello)
	}
	result.Warm = func() error {
		_, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: o.Domain, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, SupportedCurves: []tls.CurveID{tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12}})
		return err
	}
	// The plain HTTP listener serves challenges only, never the console or redirects
	// inferred from untrusted Host headers. TLS-ALPN also works when mapped to 443.
	challenges := manager.HTTPHandler(http.NotFoundHandler())
	result.Challenge = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !strings.EqualFold(host, o.Domain) {
			http.NotFound(w, r)
			return
		}
		challenges.ServeHTTP(w, r)
	})
	return result, nil
}

// autocert stores the default ECDSA key and chain together under the domain
// name. This read-only probe never contacts a CA. GetCertificate still performs
// autocert's own validation before serving the cached certificate.
func cachedCertificate(dir, domain string) bool {
	data, err := os.ReadFile(filepath.Join(dir, domain))
	if err != nil {
		return false
	}
	pair, err := tls.X509KeyPair(data, data)
	if err != nil {
		return false
	}
	if _, ok := pair.PrivateKey.(*ecdsa.PrivateKey); !ok {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	return err == nil && leaf.VerifyHostname(domain) == nil && !time.Now().Before(leaf.NotBefore) && time.Now().Before(leaf.NotAfter)
}
