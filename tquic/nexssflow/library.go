package nexssflow

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/compiler/contracts"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/transport/thttp"

	"github.com/nexssp/transportquic/tquic"
)

const ID = "tquic"

// Config controls one Flow-owned HTTP/3 listener.
type Config struct {
	Addr     string `nflow:"addr" default:":8443"`
	CertFile string `nflow:"cert_file"`
	KeyFile  string `nflow:"key_file"`
}

func init() {
	compiler.Register(ID, Bundle)
}

// Bundle creates the NFlow extension for an HTTP/3 listener. Route annotations
// come from thttp's shared :route modifier and work with both HTTP transports.
func Bundle(rawOpts map[string]string) compiler.Bundle {
	cfg, err := compiler.Decode[Config](rawOpts)
	if err != nil {
		panic("transportquic NFlow bundle: " + err.Error())
	}

	return compiler.Bundle{
		ID:        ID,
		Libraries: []action.Library{Library(cfg)},
	}
}

// Library exposes the tquic.listen action for a configured Flow listener.
func Library(cfg Config) action.Library {
	return action.Library{
		Name: "transport.tquic",
		Actions: []action.AnyAction{
			listenAction(cfg),
		},
	}
}

func listenAction(cfg Config) action.AnyAction {
	return action.New("tquic.listen", func(ctx context.Context, _ any) (any, error) {
		if ctx == nil {
			return nil, errors.New("tquic.listen: execution context is nil")
		}
		resolver := contracts.ActionResolverFromContext(ctx)
		if resolver == nil {
			return nil, errors.New("tquic.listen: action resolver is nil in execution context")
		}
		lister, ok := resolver.(interface{ Actions() []action.AnyAction })
		if !ok {
			return nil, fmt.Errorf("tquic.listen: resolver (%T) does not implement Actions()", resolver)
		}

		inner := thttp.New(cfg.Addr)
		actions := filterHTTPActions(lister.Actions(), inner.CanHandle)
		if len(actions) == 0 {
			return nil, errors.New("tquic.listen: no HTTP-bound actions found; add :route from the thttp NFlow bundle to an endpoint")
		}
		inner.Mount(actions)

		server := tquic.New(cfg.Addr, cfg.CertFile, cfg.KeyFile, inner)
		return server.Do(ctx, nil)
	}).
		Tag("transport", "quic").
		Build()
}

func filterHTTPActions(actions []action.AnyAction, canHandle func(action.Binding) bool) []action.AnyAction {
	var out []action.AnyAction
	for _, act := range actions {
		if act == nil {
			continue
		}
		if slices.ContainsFunc(act.GetBindings(), canHandle) {
			out = append(out, act)
		}
	}
	return out
}
