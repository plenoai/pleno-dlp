//go:build detector_unit

package jenkinsx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.JenkinsX {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("jx_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without jenkinsx keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("jenkinsx=" + dummyToken + "\njenkins_x_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm guards the FP shape the hardening now rejects:
// a generic high-entropy 40-80 char run sitting near a *bare* "jenkinsx"
// mention (a comment, a package name, a CI log line) with no
// `jenkinsx_token`-style assignment anchor. Before hardening the radius-256
// strings.Contains gate matched this; the armRe assignment anchor must not.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("# built on the jenkinsx platform\nbuildHash = " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for high-entropy run near bare keyword (no arm), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a 40+ char run that
// clears the alnum regex AND is armed by a real `jenkinsx_token` reference but
// is structurally low-entropy (repeated substring) must not surface.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("jenkinsx_token=abcabcabcabcabcabcabcabcabcabcabcabcabcabc")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy armed run, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
	}
}

func TestVerify_NoHost(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false when apiBase empty")
	}
}
