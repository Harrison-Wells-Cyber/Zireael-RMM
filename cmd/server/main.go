package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	project "github.com/Harrison-Wells-Cyber/Zireael-RMM"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/bootstrap"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/console"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/management"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/servertls"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/state"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		fmt.Println("Zireael-RMM", version.Current())
		return nil
	}
	if len(args) == 1 && args[0] == "licenses" {
		fmt.Print(project.ThirdPartyNotices)
		return nil
	}
	if len(args) == 0 {
		return errors.New("usage: server bootstrap --data-dir data | server serve --domain support.example [--agent-exe agent.exe]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := f.String("data-dir", "data", "private application data directory")
	listen := f.String("listen", ":8443", "HTTPS listener")
	origin := f.String("origin", "", "exact public HTTPS origin, including port if nonstandard")
	cert := f.String("tls-cert", "", "PEM server certificate chain")
	key := f.String("tls-key", "", "PEM server private key")
	domain := f.String("domain", "", "public DNS name; automatically obtain and renew a Let's Encrypt certificate by default")
	acmeListen := f.String("acme-listen", ":80", "ACME HTTP challenge listener; public port 80 must reach it (empty disables HTTP-01)")
	acmeEmail := f.String("acme-email", "", "optional ACME account contact email")
	acmeDirectory := f.String("acme-directory", "", "optional HTTPS ACME directory; defaults to Let's Encrypt production")
	agentExe := f.String("agent-exe", "", "built Windows agent executable to offer through the console")
	ifNeeded := f.Bool("if-needed", false, "bootstrap only: preserve an existing owner instead of failing")
	showToken := f.Bool("show-token", false, "bootstrap only: display a new setup token in this local terminal")
	cachedOnly := f.Bool("cached-only", false, "check only: require an existing valid automatic certificate, without contacting the CA")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] != "bootstrap" && args[0] != "serve" && args[0] != "check" {
		return errors.New("unknown command; use bootstrap, serve or check")
	}
	if args[0] != "bootstrap" && (*ifNeeded || *showToken) {
		return errors.New("--if-needed and --show-token are only valid with bootstrap")
	}
	if *cachedOnly && args[0] != "check" {
		return errors.New("--cached-only is only valid with check")
	}
	if args[0] == "check" {
		// Validate without opening the live database, binding sockets or asking a
		// CA for a certificate. The launcher supplies disposable cache storage.
		host, port, err := net.SplitHostPort(*listen)
		if err != nil {
			return err
		}
		if host != "" {
			if _, err = netip.ParseAddr(host); err != nil {
				return fmt.Errorf("listen address must be an IP address: %w", err)
			}
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return errors.New("listen port must be 1–65535")
		}
		setup, err := servertls.Configure(servertls.Options{Domain: *domain, Origin: *origin, Listen: *listen, DataDir: *dir, CertFile: *cert, KeyFile: *key, Email: *acmeEmail, DirectoryURL: *acmeDirectory})
		if err == nil && *cachedOnly && !setup.Cached {
			return errors.New("no valid automatic certificate in the cache")
		}
		return err
	}
	s, err := state.Open(*dir)
	if err != nil {
		return err
	}
	defer s.Close()
	if args[0] == "bootstrap" {
		return bootstrapOwner(s, *dir, *ifNeeded, *showToken, os.Stdout)
	}
	tlsSetup, err := servertls.Configure(servertls.Options{Domain: *domain, Origin: *origin, Listen: *listen, DataDir: *dir, CertFile: *cert, KeyFile: *key, Email: *acmeEmail, DirectoryURL: *acmeDirectory})
	if err != nil {
		return err
	}
	*origin = tlsSetup.Origin
	var artifact *bootstrap.Artifact
	if *agentExe != "" {
		artifact, err = bootstrap.Load(*agentExe)
		if err != nil {
			return err
		}
	}
	agents, err := management.New(s)
	if err != nil {
		return err
	}
	defer agents.Close()
	app, err := console.New(s, *origin)
	if err != nil {
		return err
	}
	defer app.Close()
	app.WithAgents(agents, artifact)
	server := &http.Server{Addr: *listen, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: tlsSetup.TLS}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer server.Close()
	var challenge *http.Server
	var challengeListener net.Listener
	if tlsSetup.Automatic && *acmeListen != "" {
		challengeListener, err = net.Listen("tcp", *acmeListen)
		if err != nil {
			if !tlsSetup.Cached {
				return fmt.Errorf("ACME challenge listener (public port 80 must reach it): %w", err)
			}
			slog.Warn("using cached certificate; HTTP challenge listener unavailable, restore challenge routing before renewal", "error", err)
		}
	}
	if challengeListener != nil {
		defer challengeListener.Close()
		challenge = &http.Server{Handler: tlsSetup.Challenge, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
		defer challenge.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 2)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	if challenge != nil {
		go func() { done <- challenge.Serve(challengeListener) }()
	}
	if tlsSetup.Warm != nil {
		slog.Info("obtaining or loading domain certificate", "domain", *domain)
		ready := make(chan error, 1)
		go func() { ready <- tlsSetup.Warm() }()
		select {
		case err := <-ready:
			if err != nil {
				return fmt.Errorf("automatic certificate provisioning: %w", err)
			}
		case err := <-done:
			return err
		case <-ctx.Done():
			return nil
		}
	}
	slog.Info("operator console listening", "address", *listen, "origin", *origin, "automatic_certificates", tlsSetup.Automatic)
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		agents.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if challenge != nil {
			_ = challenge.Shutdown(shutdown)
		}
		return server.Shutdown(shutdown)
	}
}
