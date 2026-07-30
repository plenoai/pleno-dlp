package detectors_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestClassifyVerifyHTTP_TransportError(t *testing.T) {
	transportErr := errors.New("dial tcp: connection refused")
	ok, err := detectors.ClassifyVerifyHTTP(nil, transportErr, []int{200}, nil)
	if ok {
		t.Error("expected verified=false on transport error")
	}
	if err == nil {
		t.Error("expected err != nil on transport error")
	}
}

func TestClassifyVerifyHTTP_AcceptCode(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK}
	ok, err := detectors.ClassifyVerifyHTTP(resp, nil, []int{200}, []int{401, 403})
	if !ok {
		t.Error("expected verified=true for 200")
	}
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
}

func TestClassifyVerifyHTTP_RejectCode(t *testing.T) {
	for _, code := range []int{401, 403, 404} {
		resp := &http.Response{StatusCode: code}
		ok, err := detectors.ClassifyVerifyHTTP(resp, nil, []int{200}, []int{401, 403, 404})
		if ok {
			t.Errorf("code %d: expected verified=false", code)
		}
		if err != nil {
			t.Errorf("code %d: expected err==nil for explicit rejection, got: %v", code, err)
		}
	}
}

func TestClassifyVerifyHTTP_TransientCodes(t *testing.T) {
	transientCodes := []int{429, 500, 502, 503, 504}
	for _, code := range transientCodes {
		resp := &http.Response{StatusCode: code}
		ok, err := detectors.ClassifyVerifyHTTP(resp, nil, []int{200}, []int{401, 403})
		if ok {
			t.Errorf("code %d: expected verified=false", code)
		}
		if err == nil {
			t.Errorf("code %d: expected err != nil for transient status", code)
		}
	}
}

func TestClassifyVerifyHTTP_UnknownCode_IsIndeterminate(t *testing.T) {
	resp := &http.Response{StatusCode: 422}
	ok, err := detectors.ClassifyVerifyHTTP(resp, nil, []int{200}, []int{401, 403})
	if ok {
		t.Error("expected verified=false for unknown code")
	}
	if err == nil {
		t.Error("expected err != nil for unknown non-transient code")
	}
}

func TestClassifyVerifyHTTP_MissingResponseIsIndeterminate(t *testing.T) {
	ok, err := detectors.ClassifyVerifyHTTP(nil, nil, []int{200}, []int{401})
	if ok {
		t.Error("expected verified=false for missing response")
	}
	if err == nil {
		t.Error("expected err != nil for missing response")
	}
}

func TestDecodeVerifyJSONRequiresBoundedExactPayload(t *testing.T) {
	var got struct {
		OK bool `json:"ok"`
	}
	if err := detectors.DecodeVerifyJSON(strings.NewReader(`{"ok":true}`), 64, &got); err != nil {
		t.Fatalf("valid response: %v", err)
	}
	if !got.OK {
		t.Fatal("valid response was not decoded")
	}

	for name, payload := range map[string]string{
		"valid prefix above limit": `{"ok":true}` + strings.Repeat(" ", 64),
		"trailing JSON":            `{"ok":true}{"ok":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			var decoded struct {
				OK bool `json:"ok"`
			}
			if err := detectors.DecodeVerifyJSON(strings.NewReader(payload), 64, &decoded); err == nil {
				t.Fatal("ambiguous response must fail closed")
			}
		})
	}
}

func TestNewVerifyHTTPClientDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("X-Api-Key", "test-value")
	resp, err := detectors.NewVerifyHTTPClient(time.Second).Do(req)
	if err != nil {
		t.Fatalf("request redirect response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if redirected.Load() {
		t.Fatal("verification client followed redirect")
	}
}
