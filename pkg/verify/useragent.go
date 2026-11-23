package verify

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
)

// MaxUserAgentSuffixLen bounds --user-agent-suffix.
const MaxUserAgentSuffixLen = 128

// DefaultUserAgent is used as the base when a request carries no
// User-Agent of its own and a suffix is configured.
const DefaultUserAgent = "pleno-dlp"

var (
	userAgentSuffix atomic.Pointer[string]
	userAgentOnce   sync.Once
)

// userAgentTransport appends the configured suffix to every outbound
// request's User-Agent. With no suffix it is a pass-through.
type userAgentTransport struct{ inner http.RoundTripper }

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if p := userAgentSuffix.Load(); p != nil && *p != "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", ApplyUserAgentSuffix(req.Header.Get("User-Agent"), *p))
	}
	return t.inner.RoundTrip(req)
}

// ApplyUserAgentSuffix returns base with suffix appended, defaulting base
// to DefaultUserAgent.
func ApplyUserAgentSuffix(base, suffix string) string {
	if suffix == "" {
		return base
	}
	if base == "" {
		base = DefaultUserAgent
	}
	return base + " " + suffix
}

// ValidateUserAgentSuffix rejects suffixes that could split headers or
// that are unreasonably long.
func ValidateUserAgentSuffix(s string) error {
	if len(s) > MaxUserAgentSuffixLen {
		return errors.New("--user-agent-suffix: longer than 128 bytes")
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return errors.New("--user-agent-suffix: control characters are not allowed")
		}
	}
	return nil
}

// SetUserAgentSuffix installs (once) a User-Agent wrapper at the base of
// http.DefaultTransport and sets the suffix it appends. Connectors and
// verifiers that use http.DefaultTransport (directly or through a nil
// http.Client.Transport) all carry the suffix. Passing "" disables it.
func SetUserAgentSuffix(s string) error {
	if err := ValidateUserAgentSuffix(s); err != nil {
		return err
	}
	if s != "" {
		userAgentOnce.Do(func() {
			http.DefaultTransport = &userAgentTransport{inner: http.DefaultTransport}
		})
	}
	userAgentSuffix.Store(&s)
	return nil
}
