// Command libpleno-dlp builds pleno-dlp's C ABI as a shared library:
//
//	go build -buildmode=c-shared -o libpleno_dlp.so ./cmd/libpleno-dlp
//
// Every exported function exchanges NUL-terminated UTF-8 JSON and returns an
// envelope {"ok": <value>} or {"error": {"code": ..., "message": ...}} that
// the caller must release with pleno_dlp_free. The envelope logic lives in
// this cgo-free file so it is unit-tested on every platform; abi.go holds
// only the thin //export shims. See docs/library.md for the contract and
// docs/adr/0001-language-bindings.md for why bindings use c-shared.
package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/plenoai/pleno-dlp/pkg/dlp"
)

func main() {}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type envelope struct {
	OK    any       `json:"ok,omitempty"`
	Error *apiError `json:"error,omitempty"`
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, dlp.ErrUnknownDetector):
		return "unknown_detector"
	case errors.Is(err, dlp.ErrNotSupported):
		return "not_supported"
	case errors.Is(err, dlp.ErrNotConfirmed):
		return "not_confirmed"
	case errors.Is(err, errBadInput):
		return "invalid_argument"
	default:
		return "internal"
	}
}

var errBadInput = errors.New("invalid argument")

func respond(v any, err error) []byte {
	var env envelope
	if err != nil {
		env.Error = &apiError{Code: errorCode(err), Message: err.Error()}
	} else {
		env.OK = v
	}
	b, mErr := json.Marshal(env)
	if mErr != nil {
		b, _ = json.Marshal(envelope{Error: &apiError{Code: "internal", Message: mErr.Error()}})
	}
	return b
}

func decode(raw string, v any) error {
	if raw == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		return errors.Join(errBadInput, err)
	}
	return nil
}

// nonNil keeps empty results serialised as [] rather than null so bindings
// can iterate without a nil check.
func nonNil(f []dlp.Finding) []dlp.Finding {
	if f == nil {
		return []dlp.Finding{}
	}
	return f
}

func scanBytes(data []byte, optsJSON string) []byte {
	var opts dlp.ScanOptions
	if err := decode(optsJSON, &opts); err != nil {
		return respond(nil, err)
	}
	f, err := dlp.ScanBytes(context.Background(), data, opts)
	return respond(nonNil(f), err)
}

func scanPaths(pathsJSON, optsJSON string) []byte {
	var paths []string
	var opts dlp.ScanOptions
	if err := decode(pathsJSON, &paths); err != nil {
		return respond(nil, err)
	}
	if len(paths) == 0 {
		return respond(nil, errors.Join(errBadInput, errors.New("paths must be a non-empty JSON array")))
	}
	if err := decode(optsJSON, &opts); err != nil {
		return respond(nil, err)
	}
	f, err := dlp.ScanPaths(context.Background(), paths, opts)
	return respond(nonNil(f), err)
}

func verify(detector, secret string) []byte {
	return respond(dlp.Verify(context.Background(), detector, secret))
}

func revoke(detector, secret, optsJSON string) []byte {
	var opts dlp.RevokeOptions
	if err := decode(optsJSON, &opts); err != nil {
		return respond(nil, err)
	}
	return respond(dlp.Revoke(context.Background(), detector, secret, opts))
}

func listDetectors() []byte { return respond(dlp.Detectors(), nil) }

func version() []byte { return respond(dlp.APIVersion, nil) }
