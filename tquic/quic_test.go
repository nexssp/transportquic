package tquic_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nexssp/flow/compiler/contracts"
	"github.com/nexssp/transport/thttp"
	"github.com/nexssp/transportquic/tquic"
	"github.com/quic-go/quic-go/http3"
)

func TestAltSvcMiddleware(t *testing.T) {
	t.Parallel()

	handler := tquic.AltSvcMiddleware(":8443")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if got, want := response.Header().Get("Alt-Svc"), `h3=":8443"; ma=86400`; got != want {
		t.Fatalf("Alt-Svc = %q, want %q", got, want)
	}
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestAltSvcMiddlewareIgnoresInvalidAuthority(t *testing.T) {
	t.Parallel()

	for _, authority := range []string{"", "bad", ":0", ":70000", "\"\r\nX-Bad: y"} {
		t.Run(authority, func(t *testing.T) {
			handler := tquic.AltSvcMiddleware(authority)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
			if got := response.Header().Get("Alt-Svc"); got != "" {
				t.Fatalf("Alt-Svc = %q, want no header", got)
			}
		})
	}
}

func TestTransportMetadataAndBinding(t *testing.T) {
	t.Parallel()

	inner := thttp.New(":0")
	transport := tquic.New("127.0.0.1:8443", "cert.pem", "key.pem", inner)
	if !transport.CanHandle(thttp.GET("/healthz")) {
		t.Fatal("HTTP route should be handled by the wrapped transport")
	}
	if got := transport.Scheme(); got != "https" {
		t.Fatalf("Scheme() = %q, want https", got)
	}
	if got := transport.Addr(); got != "127.0.0.1:8443" {
		t.Fatalf("Addr() = %q", got)
	}
	if got := transport.String(); got != "quic(127.0.0.1:8443)" {
		t.Fatalf("String() = %q", got)
	}
	if tquic.New("", "", "", nil).CanHandle(thttp.GET("/healthz")) {
		t.Fatal("transport without an inner HTTP adapter must not handle bindings")
	}
}

func TestDoRejectsMissingConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := tquic.New(":8443", "cert.pem", "key.pem", thttp.New(":0")).Do(nil, nil); err == nil {
		t.Fatal("Do(nil) should fail")
	}
	if _, err := tquic.New(":8443", "cert.pem", "key.pem", nil).Do(context.Background(), nil); err == nil {
		t.Fatal("Do without an inner HTTP transport should fail")
	}
	if _, err := tquic.New(":8443", "", "", thttp.New(":0")).Do(context.Background(), nil); err == nil {
		t.Fatal("Do without TLS files should fail")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tquic.New(":8443", "", "", nil).Do(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Do on canceled context = %v, want context.Canceled", err)
	}
}

func TestDoDoesNotSignalReadyWhenBindFails(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _ := writeTestCertificate(t)
	signal := contracts.NewReadySignal()
	ctx := contracts.WithServiceReady(context.Background(), signal)
	_, err := tquic.New("127.0.0.1:not-a-port", certFile, keyFile, thttp.New(":0")).Do(ctx, nil)
	if err == nil {
		t.Fatal("Do should fail to bind an invalid address")
	}
	select {
	case <-signal.Done():
		t.Fatal("server signaled ready despite bind failure")
	default:
	}
}

func TestDoServesHTTP3AndStopsOnCancellation(t *testing.T) {
	certFile, keyFile, roots := writeTestCertificate(t)
	addr := freeUDPAddress(t)
	inner := thttp.New(":0")
	inner.Mux().HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ready := contracts.NewReadySignal()
	ctx, cancel := context.WithCancel(contracts.WithServiceReady(context.Background(), ready))
	done := make(chan error, 1)
	go func() {
		_, err := tquic.New(addr, certFile, keyFile, inner).Do(ctx, nil)
		done <- err
	}()

	select {
	case <-ready.Done():
	case err := <-done:
		cancel()
		t.Fatalf("HTTP/3 transport stopped before readiness: %v", err)
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("HTTP/3 transport did not signal readiness")
	}

	roundTripper := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	client := &http.Client{Transport: roundTripper}
	if err := getHealth(client, ctx, "https://"+addr+"/healthz"); err != nil {
		_ = roundTripper.Close()
		cancel()
		<-done
		t.Fatal(err)
	}
	if err := roundTripper.Close(); err != nil {
		t.Fatalf("close HTTP/3 client: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Do error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/3 transport did not stop after cancellation")
	}
}

func getHealth(client *http.Client, ctx context.Context, url string) error {
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		requestCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, http.NoBody)
		if err != nil {
			cancel()
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			cancel()
			if response.StatusCode != http.StatusNoContent {
				return errors.New("unexpected HTTP/3 health response: " + response.Status)
			}
			return nil
		}
		cancel()
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("HTTP/3 health request failed before deadline: " + lastErr.Error())
}

func freeUDPAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func writeTestCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	certFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return certFile, keyFile, roots
}
