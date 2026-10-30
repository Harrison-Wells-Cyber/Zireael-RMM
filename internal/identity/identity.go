// Package identity uses standard X.509 certificates for deployment and device identity.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/state"
)

const ServerName = "rmm.internal"

type material struct {
	Certificate []byte
	Key         []byte
}
type Authority struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	PEM    []byte
	mu     sync.Mutex
	server *tls.Certificate
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func Load(store *state.Store) (*Authority, error) {
	raw, err := store.PrivateValue("deployment-ca-v1", func() ([]byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		number, err := serial()
		if err != nil {
			return nil, err
		}
		now := time.Now()
		cert := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: "Zireael-RMM deployment CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		return json.Marshal(material{Certificate: certPEM(der), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})})
	})
	if err != nil {
		return nil, err
	}
	var m material
	if err = json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(m.Certificate, m.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil || !time.Now().Before(cert.NotAfter) {
		return nil, errors.New("invalid or expired deployment CA")
	}
	return &Authority{cert: cert, key: key, PEM: m.Certificate}, nil
}

// ServerCertificate renews the short-lived inner server certificate on demand.
func (a *Authority) ServerCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.server != nil && time.Until(a.server.Leaf.NotAfter) > 24*time.Hour {
		return a.server, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	number, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expires := now.Add(7 * 24 * time.Hour)
	if expires.After(a.cert.NotAfter) {
		expires = a.cert.NotAfter
	}
	if !expires.After(now) {
		return nil, errors.New("deployment CA expired")
	}
	template := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: ServerName}, DNSNames: []string{ServerName}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	a.server = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return a.server, nil
}

func ParseRequest(der []byte) (*x509.CertificateRequest, string, error) {
	if len(der) > 4096 {
		return nil, "", errors.New("certificate request too large")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, "", err
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, "", err
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, "", errors.New("ECDSA P-256 device key required")
	}
	hash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	return csr, hex.EncodeToString(hash[:]), nil
}

// CSR identity, usages, names and extensions are ignored. Only its proven key is used.
func (a *Authority) IssueDevice(id string, csr *x509.CertificateRequest) ([]byte, string, time.Time, error) {
	number, err := serial()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	now := time.Now()
	expires := now.AddDate(1, 0, 0).Truncate(time.Second)
	if expires.After(a.cert.NotAfter) {
		expires = a.cert.NotAfter
	}
	if !expires.After(now) {
		return nil, "", time.Time{}, errors.New("deployment CA expired")
	}
	template := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: id}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, csr.PublicKey, a.key)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return certPEM(der), Fingerprint(der), expires, nil
}

func Fingerprint(der []byte) string { hash := sha256.Sum256(der); return hex.EncodeToString(hash[:]) }

func NewDeviceKey() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), csr, nil
}
