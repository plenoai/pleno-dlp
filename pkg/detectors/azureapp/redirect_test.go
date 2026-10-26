//go:build detector_unit

package azureapp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestVerifyOAuth2_DoesNotFollowRedirect(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		var hit atomic.Bool
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hit.Store(true)
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"x"}`))
		}))
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/steal", code)
		}))

		prev := tokenURLFormat
		tokenURLFormat = origin.URL + "/%s/oauth2/v2.0/token"
		ok, err := verifyOAuth2(context.Background(), "tenant", "client-id", "super-secret")
		tokenURLFormat = prev
		origin.Close()
		target.Close()

		if ok || err != nil {
			t.Fatalf("status %d: verifyOAuth2 = (%v, %v), want (false, nil)", code, ok, err)
		}
		if hit.Load() {
			t.Fatalf("status %d: redirect target received the credential request", code)
		}
	}
}
