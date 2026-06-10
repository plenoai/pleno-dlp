package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	testWebhookScheme = "https://"
	testSlackHost     = "hooks.slack.com"
	testSlackGovHost  = "hooks.slack-gov.com"
	testTeamSegment   = "T01234567"
	testBotSegment    = "B01234567"
	testSecretPrefix  = "abcdefghijkl"
	testSecretSuffix  = "mnopqrstuvwx"
)

var testSecretSegment = testSecretPrefix + testSecretSuffix

var dummyWebhook = testWebhookURL(testSlackHost, testSecretSegment)

func testWebhookURL(host, secret string) string {
	return testWebhookScheme + host + "/services/" + testTeamSegment + "/" + testBotSegment + "/" + secret
}

func testWebhookPath(secret string) string {
	return "/services/" + testTeamSegment + "/" + testBotSegment + "/" + secret
}

func TestWebhookType(t *testing.T) {
	if (WebhookScanner{}).Type() != detectors.SlackWebhook {
		t.Fatal("type mismatch")
	}
}

func TestWebhookKeywords(t *testing.T) {
	if got := (WebhookScanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestWebhookFromDataPositive(t *testing.T) {
	res, err := WebhookScanner{}.FromData(context.Background(), false, []byte("SLACK_WEBHOOK_URL="+dummyWebhook))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyWebhook {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if res[0].Redacted == dummyWebhook {
		t.Fatal("expected redacted value to hide secret segment")
	}
}

func TestWebhookFromDataSlackGov(t *testing.T) {
	webhook := testWebhookURL(testSlackGovHost, testSecretSegment)
	res, err := WebhookScanner{}.FromData(context.Background(), false, []byte("webhook="+webhook))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != webhook {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestWebhookFromDataDedup(t *testing.T) {
	body := []byte(dummyWebhook + "\n" + dummyWebhook)
	res, err := WebhookScanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 deduped result, got %d", len(res))
	}
}

func TestWebhookFromDataDoesNotOvercapture(t *testing.T) {
	body := []byte(dummyWebhook + "extra")
	res, err := WebhookScanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestWebhookFromDataNegative(t *testing.T) {
	body := []byte(testWebhookURL("example.com", testSecretSegment))
	res, err := WebhookScanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestWebhookVerifyActive(t *testing.T) {
	srv := webhookVerifyServer(t, http.StatusBadRequest, "invalid_payload")
	defer srv.Close()

	v, err := WebhookScanner{}.Verify(context.Background(), dummyWebhook)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestWebhookVerifyNoText(t *testing.T) {
	srv := webhookVerifyServer(t, http.StatusBadRequest, "no_text")
	defer srv.Close()

	v, err := WebhookScanner{}.Verify(context.Background(), dummyWebhook)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestWebhookVerifyRevoked(t *testing.T) {
	srv := webhookVerifyServer(t, http.StatusNotFound, "no_service")
	defer srv.Close()

	v, err := WebhookScanner{}.Verify(context.Background(), dummyWebhook)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestWebhookVerifyRejectsNonSlackHost(t *testing.T) {
	v, err := WebhookScanner{}.Verify(
		context.Background(),
		testWebhookURL("example.com", testSecretSegment),
	)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestWebhookVerifyRejectsMalformedSlackURL(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	old := slackWebhookVerifyBase
	slackWebhookVerifyBase = srv.URL
	t.Cleanup(func() { slackWebhookVerifyBase = old })

	v, err := WebhookScanner{}.Verify(
		context.Background(),
		testWebhookURL(testSlackHost, "short"),
	)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
	if called {
		t.Fatal("expected malformed URL to be rejected before HTTP call")
	}
}

func TestWebhookFromDataVerify(t *testing.T) {
	srv := webhookVerifyServer(t, http.StatusBadRequest, "invalid_payload")
	defer srv.Close()

	res, err := WebhookScanner{}.FromData(context.Background(), true, []byte(dummyWebhook))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected verified=true")
	}
}

func webhookVerifyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testWebhookPath(testSecretSegment) {
			t.Errorf("path mismatch: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method mismatch: %s", r.Method)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))

	old := slackWebhookVerifyBase
	slackWebhookVerifyBase = srv.URL
	t.Cleanup(func() { slackWebhookVerifyBase = old })
	return srv
}
