package nexssflow

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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/compiler/contracts"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/transport/thttp"
	thttpflow "github.com/nexssp/transport/thttp/nexssflow"
	"github.com/nexssp/transportquic/tquic"
	"github.com/quic-go/quic-go/http3"
)

func TestBundleRegistersListenerAndUsesSharedRouteModifier(t *testing.T) {
	httpBundle := thttpflow.Bundle(map[string]string{})
	quicBundle := Bundle(map[string]string{
		"addr":      ":9443",
		"cert_file": "server.crt",
		"key_file":  "server.key",
	})
	if quicBundle.ID != ID {
		t.Fatalf("bundle ID = %q, want %q", quicBundle.ID, ID)
	}
	if len(quicBundle.Libraries) != 1 || quicBundle.Libraries[0].Name != "transport.tquic" {
		t.Fatalf("unexpected NFlow libraries: %+v", quicBundle.Libraries)
	}
	if got := quicBundle.Libraries[0].Actions[0].Describe().Name; got != "tquic.listen" {
		t.Fatalf("listener action = %q, want tquic.listen", got)
	}
	if len(quicBundle.Modifiers) != 0 {
		t.Fatalf("QUIC bundle must not duplicate the shared :route modifier: %+v", quicBundle.Modifiers)
	}

	modifiers := append(append([]compiler.Modifier{}, httpBundle.Modifiers...), quicBundle.Modifiers...)
	table := compiler.NewModifierTable(modifiers...)
	if _, ok := table.ByName("route"); !ok {
		t.Fatal("thttp bundle did not register the shared :route modifier")
	}
}

func TestSharedRouteServesOverHTTPAndHTTP3(t *testing.T) {
	httpBundle := thttpflow.Bundle(map[string]string{})
	if len(httpBundle.Modifiers) != 1 || httpBundle.Modifiers[0].Name != "route" {
		t.Fatalf("thttp route modifier = %+v, want exactly :route", httpBundle.Modifiers)
	}
	route := httpBundle.Modifiers[0]
	endpointBuilder := action.New("test.health", func(context.Context, any) (any, error) {
		return map[string]string{"status": "ok"}, nil
	})
	if err := route.Apply(endpointBuilder, "GET /health"); err != nil {
		t.Fatalf("apply shared route: %v", err)
	}
	endpoint := endpointBuilder.Build()

	tcpInner := thttp.New(":0")
	quicInner := thttp.New(":0")
	quicTransport := tquic.New("127.0.0.1:8443", "server.crt", "server.key", quicInner)
	bindings := endpoint.GetBindings()
	if len(bindings) != 1 || !tcpInner.CanHandle(bindings[0]) || !quicTransport.CanHandle(bindings[0]) {
		t.Fatalf("shared route bindings are not supported by both listeners: %+v", bindings)
	}
	quicActions := filterHTTPActions([]action.AnyAction{endpoint}, quicTransport.CanHandle)
	if len(quicActions) != 1 || quicActions[0] != endpoint {
		t.Fatalf("QUIC listener did not discover the shared route: %+v", quicActions)
	}
	tcpInner.Mount([]action.AnyAction{endpoint})
	quicInner.Mount(quicActions)

	tcpServer := httptest.NewServer(tcpInner.Handler())
	defer tcpServer.Close()

	certFile, keyFile, roots := writeTestCertificate(t)
	udpAddr := freeUDPAddress(t)
	quicTransport = tquic.New(udpAddr, certFile, keyFile, quicInner)
	ready := contracts.NewReadySignal()
	ctx, cancel := context.WithCancel(contracts.WithServiceReady(context.Background(), ready))
	done := make(chan error, 1)
	go func() {
		_, err := quicTransport.Do(ctx, nil)
		done <- err
	}()
	stopped := false
	stopServer := func() {
		if stopped {
			return
		}
		cancel()
		select {
		case err := <-done:
			stopped = true
			if !errors.Is(err, context.Canceled) {
				t.Errorf("HTTP/3 listener stopped with %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("HTTP/3 listener did not stop after cancellation")
		}
	}
	defer stopServer()

	select {
	case <-ready.Done():
	case err := <-done:
		stopped = true
		t.Fatalf("HTTP/3 listener stopped before readiness: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/3 listener did not become ready")
	}

	roundTripper := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer roundTripper.Close()
	assertHealthResponse(t, http.DefaultClient, tcpServer.URL+"/health")
	assertHealthResponse(t, &http.Client{Transport: roundTripper}, "https://"+udpAddr+"/health")
}

func assertHealthResponse(t *testing.T, client *http.Client, url string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != `{"status":"ok"}` {
		t.Fatalf("GET %s = %s %q, want 200 {\"status\":\"ok\"}", url, response.Status, strings.TrimSpace(string(body)))
	}
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
