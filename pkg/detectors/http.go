package detectors

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// NewVerifyHTTPClient returns an HTTP client that never follows redirects.
// Verification requests routinely carry credentials in provider-specific
// headers or query parameters, which net/http may otherwise forward to a
// redirect target.
func NewVerifyHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ClassifyVerifyHTTP normalises an HTTP verification response into a
// (verified, err) pair that distinguishes transient failures from explicit
// rejections.
//
//   - Transport error (resp == nil)     → (false, err)            // network / TLS failure
//   - resp.StatusCode in acceptCodes    → (true,  nil)            // valid credential
//   - resp.StatusCode in rejectCodes    → (false, nil)            // explicit rejection
//   - resp.StatusCode >= 500            → (false, fmt.Errorf(…))  // provider-side transient
//   - resp.StatusCode == 429            → (false, fmt.Errorf(…))  // rate-limit transient
//   - anything else                     → (false, fmt.Errorf(…))  // ambiguous response
//
// acceptCodes must include every status code that means "credential is valid"
// (commonly []int{200}). rejectCodes lists statuses that are unambiguously
// invalid (commonly []int{401, 403, 404}). Any undeclared status is ambiguous
// and must not be collapsed into a provider-confirmed negative.
//
// Callers pass transportErr from http.Client.Do. When transportErr != nil the
// resp argument is unused and may be nil.
func ClassifyVerifyHTTP(resp *http.Response, transportErr error, acceptCodes, rejectCodes []int) (bool, error) {
	if transportErr != nil {
		return false, transportErr
	}
	if resp == nil {
		return false, fmt.Errorf("verify: missing HTTP response")
	}
	code := resp.StatusCode
	for _, c := range acceptCodes {
		if code == c {
			return true, nil
		}
	}
	if isTransient(code) {
		return false, fmt.Errorf("verify: transient HTTP %d", code)
	}
	for _, c := range rejectCodes {
		if code == c {
			return false, nil
		}
	}
	return false, fmt.Errorf("verify: ambiguous HTTP %d", code)
}

// DecodeVerifyJSON reads one bounded JSON response into dst. Verification
// endpoints are untrusted network inputs: accepting a valid prefix while
// silently ignoring an oversized or trailing payload can turn an ambiguous
// response into a positive credential verdict.
func DecodeVerifyJSON(body io.Reader, maxBytes int64, dst any) error {
	if body == nil {
		return fmt.Errorf("verify: missing response body")
	}
	if maxBytes <= 0 {
		return fmt.Errorf("verify: invalid JSON response limit %d", maxBytes)
	}
	payload, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("verify: read JSON response: %w", err)
	}
	if int64(len(payload)) > maxBytes {
		return fmt.Errorf("verify: JSON response exceeds %d bytes", maxBytes)
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("verify: decode JSON response: %w", err)
	}
	return nil
}

// isTransient reports whether an HTTP status code represents a condition that
// is temporary and not an authoritative "invalid credential" verdict from the
// provider. Callers should propagate these as errors so the engine can mark
// the finding "verification failed" rather than "verified-not-valid".
func isTransient(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}
