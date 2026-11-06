# Nexss Transport QUIC

`transportquic` serves an existing Nexss `thttp.Transport` over HTTP/3 (QUIC). It reuses the same action bindings, routes, and HTTP middleware; it does not add a second router.

## Requirements

- Go 1.27.3 or newer.
- A TLS certificate and private key valid for the public hostname.
- UDP reachability on the configured address. TCP access alone is not sufficient for HTTP/3.

Install the module:

```sh
go get github.com/nexssp/transportquic@latest
```

## Use

```go
httpTransport := thttp.New(":8443")
httpTransport.Mount(actions)

quicTransport := tquic.New(":8443", "server.crt", "server.key", httpTransport)
_, err := quicTransport.Do(ctx, nil)
```

`Do` binds UDP, reports readiness after binding, and blocks until `ctx` is canceled. It gracefully shuts down active HTTP/3 connections for up to ten seconds, then closes the server. It returns the context error after normal cancellation, matching the core `thttp` transport.

An HTTPS endpoint can advertise the HTTP/3 authority with `tquic.AltSvcMiddleware(":8443")`. Use that middleware on the existing HTTPS handler that clients reach first; this module itself only serves HTTP/3 over UDP. The middleware ignores malformed authorities.

## Notes

HTTP/3 requires TLS 1.3. Use a publicly trusted certificate in production and keep the private key outside source control. Configure firewalls and load balancers to pass UDP on the QUIC port. If UDP is blocked, clients need a separate HTTPS/TCP endpoint as a fallback.

## NexssFlow

The `tquic/nexssflow` package adds a `tquic.listen` action and reuses the shared `:route` modifier from the thttp NFlow bundle. It deliberately does not register a second route modifier: Flow v0.70.0 rejects duplicate modifier names, and both listeners can consume the same HTTP binding. The thttp bundle owns `:route` and provides the TCP listener; the QUIC adapter serves those same routes over UDP/HTTP/3.

```nflow
@require github.com/nexssp/transport/thttp/nexssflow v0.11.1 { addr: ":8080" }
@require ../transportquic/tquic/nexssflow { addr: ":8443", cert_file: "./certs/server.crt", key_file: "./certs/server.key" }

@pipeline health
  :route="GET /health"
  const @{ value: { status: "ok" } }
@end

(
  thttp.listen
  & tquic.listen
)
```

The HTTP route declaration is shared; the listener addresses and protocols are not. This starts TCP HTTP on port 8080 and HTTP/3 over UDP on port 8443. For HTTP/3 discovery, apply `tquic.AltSvcMiddleware` to an existing HTTPS/TCP handler clients reach first. See the separate NFlow examples for local certificate setup and run commands.

## Development

Install [Task](https://taskfile.dev/) and golangci-lint v2.14.0, the version used by CI:

```sh
go install github.com/go-task/task/v3/cmd/task@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
```

Run `task tools` to install the optional test-output and vulnerability tools. Use `task build`, `task test`, `task lint`, and `task fmt` for individual checks; `task ci` runs lint, race-enabled tests, and the vulnerability scan. The `.golangci.yml` policy follows `nexssp/flow`.
