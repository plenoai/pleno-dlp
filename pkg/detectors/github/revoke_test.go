// Additional revoke tests that cover transport-level behaviour (network
// failure, rate-limit) on top of the response-code matrix already
// exercised in github_test.go.
package github

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestRevoke_RateLimited asserts 429 → hard error, no retry. Same
// policy as Verify (don't stall the scan).
func TestRevoke_RateLimited(t *testing.T) {
	srv, _ := revokeServer(t, http.StatusTooManyRequests)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	SetRevokeCredentials(testClientID, testClientSecret)
	t.Cleanup(func() { SetRevokeCredentials("", "") })

	_, err := Scanner{}.Revoke(context.Background(), dummyClassic)
	if err == nil {
		t.Fatal("429 must surface as a hard error")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error must mention HTTP 429: %v", err)
	}
}

// TestRevoke_NetworkError asserts that a transport-level failure flows
// through the second return value (not RevokeResult.Err) so callers
// can distinguish "we couldn't reach the provider" from "the provider
// said no".
func TestRevoke_NetworkError(t *testing.T) {
	prev := apiBase
	apiBase = "http://127.0.0.1:1" // refused
	t.Cleanup(func() { apiBase = prev })
	SetRevokeCredentials(testClientID, testClientSecret)
	t.Cleanup(func() { SetRevokeCredentials("", "") })

	got, err := Scanner{}.Revoke(context.Background(), dummyClassic)
	if err == nil {
		t.Fatal("network failure must surface via the second return value")
	}
	if got.Revoked {
		t.Error("must not report Revoked=true on transport failure")
	}
	if got.Err != nil {
		t.Errorf("transport failures must not populate RevokeResult.Err: %v", got.Err)
	}
}
