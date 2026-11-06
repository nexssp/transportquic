// Package tquic serves an existing Nexss HTTP transport over HTTP/3.
package tquic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nexssp/flow/compiler/contracts"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/transport"
	"github.com/nexssp/transport/thttp"
	"github.com/quic-go/quic-go/http3"
)

const shutdownTimeout = 10 * time.Second

var _ transport.Transport = (*Transport)(nil)

// Transport reuses a configured thttp router and serves it over HTTP/3.
type Transport struct {
	addr     string
	certFile string
	keyFile  string
	inner    *thttp.Transport
}

// New creates an HTTP/3 transport. Do validates the address, certificate, key,
// and inner HTTP transport before binding its UDP listener.
func New(addr, certFile, keyFile string, inner *thttp.Transport) *Transport {
	return &Transport{
		addr:     addr,
		certFile: certFile,
		keyFile:  keyFile,
		inner:    inner,
	}
}

func (t *Transport) CanHandle(b action.Binding) bool {
	return t != nil && t.inner != nil && t.inner.CanHandle(b)
}

func (t *Transport) String() string {
	if t == nil {
		return "quic(<nil>)"
	}
	return "quic(" + t.addr + ")"
}

// Scheme returns the secure URL scheme used by HTTP/3.
func (t *Transport) Scheme() string { return "https" }

// Addr returns the UDP bind address.
func (t *Transport) Addr() string {
	if t == nil {
		return ""
	}
	return t.addr
}

// Mount delegates action registration to the wrapped HTTP transport.
func (t *Transport) Mount(actions []action.AnyAction) {
	if t != nil && t.inner != nil {
		t.inner.Mount(actions)
	}
}

// Do serves the wrapped HTTP handler until ctx is canceled. The listener uses
// UDP, as required by QUIC, and shutdown returns ctx.Err like the core HTTP
// transport.
func (t *Transport) Do(ctx context.Context, _ any) (any, error) {
	if ctx == nil {
		return nil, errors.New("http/3 server context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t == nil {
		return nil, errors.New("http/3 transport is nil")
	}
	if t.inner == nil {
		return nil, errors.New("http/3 inner HTTP transport is nil")
	}
	if strings.TrimSpace(t.addr) == "" {
		return nil, errors.New("http/3 listen address is empty")
	}
	if t.certFile == "" || t.keyFile == "" {
		return nil, errors.New("http/3 TLS certificate and key are required")
	}

	certificate, err := tls.LoadX509KeyPair(t.certFile, t.keyFile)
	if err != nil {
		return nil, fmt.Errorf("http/3 load TLS certificate: %w", err)
	}

	var listenConfig net.ListenConfig
	packetConn, err := listenConfig.ListenPacket(ctx, "udp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("http/3 listen on %q: %w", t.addr, err)
	}
	defer packetConn.Close()

	server := &http3.Server{
		Addr:    t.addr,
		Handler: t.inner.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(packetConn)
	}()

	contracts.SignalReady(ctx)
	select {
	case serveErr := <-serveDone:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return nil, fmt.Errorf("http/3 server stopped: %w", serveErr)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("http/3 server stopped before context cancellation")
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		_ = server.Close()
	}
	_ = packetConn.Close()
	serveErr := <-serveDone

	if shutdownErr != nil {
		return nil, fmt.Errorf("http/3 graceful shutdown failed: %w", shutdownErr)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && ctx.Err() == nil {
		return nil, fmt.Errorf("http/3 server stopped: %w", serveErr)
	}
	return nil, ctx.Err()
}
