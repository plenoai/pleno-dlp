package cloudinary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyKey    = "123456789012345"
	dummySecret = "abcdefghijklmnopqrstuvwxyz0123"
	dummyCloud  = "demo-cloud"
)

var dummyURL = "cloudinary://" + dummyKey + ":" + dummySecret + "@" + dummyCloud

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Cloudinary {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("CLOUDINARY_URL=" + dummyURL)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyKey || string(res[0].RawV2) != dummySecret {
		t.Fatalf("pair mismatch")
	}
	if res[0].ExtraData["cloud_name"] != dummyCloud {
		t.Fatalf("cloud mismatch: %v", res[0].ExtraData)
	}
}

func TestFromData_NoURL(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("cloudinary nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0 without URL, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte(dummyURL + "\n" + dummyURL)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, dummyCloud) {
			t.Errorf("expected cloud in path: %s", r.URL.Path)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyKey || p != dummySecret {
			t.Errorf("basic auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret+"@"+dummyCloud)
	if err != nil || !v {
		t.Fatalf("verified expected true: err=%v v=%v", err, v)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret+"@"+dummyCloud)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_BadFormat(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), "no-colon-or-at")
	if v {
		t.Fatal("expected verified=false for missing format")
	}
}
