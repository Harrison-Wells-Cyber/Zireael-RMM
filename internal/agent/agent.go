// Package agent implements enrollment and the device's outbound control connection.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/identity"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/state"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/tunnel"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
)

type Invite struct {
	Server string `json:"server"`
	CA     []byte `json:"ca"`
	Token  string `json:"token"`
	Mode   string `json:"mode"`
}

type Config struct {
	Server      string `json:"server"`
	CA          []byte `json:"ca"`
	DeviceID    string `json:"deviceID"`
	Mode        string `json:"mode"`
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"privateKey"`
	PendingCode string `json:"-"`
}

func ValidServer(server string) bool {
	u, err := url.Parse(server)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.Opaque == ""
}

// Enroll uses an existing locally generated key/CSR so a lost response can be
// retried without enrolling another identity. The key never leaves the device.
func Enroll(ctx context.Context, in Invite, key, csr []byte, outerRoots *x509.CertPool) (Config, error) {
	var config Config
	if !ValidServer(in.Server) || !state.ValidMode(in.Mode) || len(in.Token) != 43 {
		return config, errors.New("invalid enrollment configuration")
	}
	client, err := tunnel.NewEnrollmentClient(in.CA, identity.ServerName)
	if err != nil {
		return config, err
	}
	conn, err := client.Dial(ctx, in.Server+"/agent/v1/enroll", outerRoots)
	if err != nil {
		return config, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	hostname, _ := os.Hostname()
	if err = wire.Write(conn, wire.EnrollmentRequest{Token: in.Token, CSR: csr, Hostname: hostname}); err != nil {
		return config, err
	}
	var response wire.EnrollmentResponse
	if err = wire.Read(conn, &response); err != nil {
		return config, err
	}
	if response.Error != "" {
		return config, errors.New("enrollment rejected or expired")
	}
	if response.Mode != in.Mode || len(response.DeviceID) != 64 {
		return config, errors.New("unexpected enrollment identity")
	}
	config = Config{Server: in.Server, CA: in.CA, DeviceID: response.DeviceID, Mode: in.Mode, Certificate: response.Certificate, PrivateKey: key}
	if response.Pending {
		config.PendingCode = response.PairingCode
	}
	if _, err = config.identity(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) identity() (tls.Certificate, error) {
	pair, err := tls.X509KeyPair(c.Certificate, c.PrivateKey)
	if err != nil {
		return pair, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return pair, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CA) {
		return pair, errors.New("invalid deployment CA")
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return pair, err
	}
	if leaf.Subject.CommonName != c.DeviceID || leaf.IsCA {
		return pair, errors.New("device certificate identity mismatch")
	}
	return pair, nil
}

func (c Config) Validate() error {
	if !ValidServer(c.Server) || !state.ValidMode(c.Mode) || len(c.DeviceID) != 64 {
		return errors.New("invalid saved agent configuration")
	}
	_, err := c.identity()
	return err
}

// Session returns established=true after an authenticated inner connection was
// established. Temporary agents stop if it ends, including a lost greeting.
func Session(ctx context.Context, config Config, hello wire.Hello, outerRoots *x509.CertPool, connected func(), handlers ...func(context.Context, net.Conn)) (established bool, err error) {
	ctx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancelSession()
	pair, err := config.identity()
	if err != nil {
		return false, err
	}
	client, err := tunnel.NewClient(pair, config.CA, identity.ServerName)
	if err != nil {
		return false, err
	}
	conn, err := client.Dial(ctx, config.Server+"/agent/v1/connect", outerRoots)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()); _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	hello.Version, hello.Mode = wire.Version, config.Mode
	if err = wire.Write(conn, hello); err != nil {
		return true, err
	}
	var response wire.Control
	if err = wire.Read(conn, &response); err != nil {
		return true, err
	}
	if response.Type != "ready" || response.DeviceID != config.DeviceID {
		return true, errors.New("unexpected server greeting")
	}
	if connected != nil {
		connected()
	}
	readDone := make(chan error, 1)
	readerStopped := make(chan struct{})
	defer func() { cancelSession(); conn.Close(); <-readerStopped }()
	slots := make(chan struct{}, 3)
	go func() {
		defer close(readerStopped)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
			var message wire.Control
			if err := wire.Read(conn, &message); err != nil {
				readDone <- err
				return
			}
			if message.Type == "open" && message.DeviceID == "" && len(message.Ticket) == 43 && len(handlers) == 1 {
				select {
				case slots <- struct{}{}:
					workers.Go(func() {
						defer func() { <-slots }()
						stream, err := client.Dial(ctx, config.Server+"/agent/v1/operation", outerRoots)
						if err != nil {
							return
						}
						defer stream.Close()
						stop := context.AfterFunc(ctx, func() { stream.Close() })
						defer stop()
						_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
						if wire.Write(stream, wire.Open{Ticket: message.Ticket}) == nil {
							handlers[0](ctx, stream)
						}
					})
				default:
					readDone <- errors.New("operation capacity exceeded")
					return
				}
				continue
			}
			if message.Type != "pong" || message.DeviceID != "" || message.Ticket != "" {
				readDone <- errors.New("unexpected control response")
				return
			}
		}
	}()
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case err := <-readDone:
			return true, err
		case <-timer.C:
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err = wire.Write(conn, wire.Control{Type: "ping"}); err != nil {
			return true, err
		}
	}
}

func Run(ctx context.Context, config Config, hello wire.Hello, status func(string), handlers ...func(context.Context, net.Conn)) error {
	if status == nil {
		status = func(string) {}
	}
	if err := config.Validate(); err != nil {
		return err
	}
	delay := time.Second
	for {
		established, err := Session(ctx, config, hello, nil, func() { status("Connected to support server") }, handlers...)
		if ctx.Err() != nil {
			return nil
		}
		if established && config.Mode == "temporary" {
			status("Support connection ended; temporary agent stopped")
			return nil
		}
		if established {
			delay = time.Second
		}
		if err != nil {
			status(fmt.Sprintf("Connection unavailable; retrying in %s", delay))
		}
		timer := time.NewTimer(delay + time.Duration(rand.Int64N(int64(delay/2))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}
