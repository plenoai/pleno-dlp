package signalwire

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "abcdef0123456789abcdef01ABCDEF"
const dummyTok = "PT0123456789abcdef0123456789abcdef"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.SignalWire {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("SIGNALWIRE_PROJECT=" + dummyID + "\nSIGNALWIRE_TOKEN=" + dummyTok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummyTok {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("PROJECT=" + dummyID + "\nTOKEN=" + dummyTok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: two padded,
// low-information runs sit right next to documented assignment keywords and
// clear the bare [A-Za-z0-9]{24,128} regex, but neither reaches 3.5 bits/char
// so the pair must not be emitted. Before the FP-hardening this matched.
func TestFromData_LowEntropyRejected(t *testing.T) {
	const lowID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const lowTok = "0000000000000000000000000000000000000000000000000000"
	body := []byte("SIGNALWIRE_PROJECT=" + lowID + "\nSIGNALWIRE_TOKEN=" + lowTok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy rejected), got %d", len(res))
	}
}

// TestFromData_BareKeywordFarAway guards the radius shrink (256->64) plus the
// assignment-anchor arm regex: a high-entropy pair appears in the same chunk
// as a prose mention of signalwire, but the keyword is neither adjacent nor in
// an assignment form, so the pair must not be emitted.
func TestFromData_BareKeywordFarAway(t *testing.T) {
	gap := make([]byte, 200)
	for i := range gap {
		gap[i] = ' '
	}
	body := []byte("we evaluated signalwire last quarter." + string(gap) +
		"PROJECT=" + dummyID + "\nTOKEN=" + dummyTok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (keyword out of radius / not an assignment), got %d", len(res))
	}
}

func TestVerify_Disabled_Default(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyTok)
	if v {
		t.Fatal("expected verified=false default")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummyID || p != dummyTok {
			t.Errorf("basic-auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyTok)
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyTok)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyTok)
	if v {
		t.Fatal("expected verified=false")
	}
}
