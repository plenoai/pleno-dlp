package pingidentity

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a high-entropy RFC4122 v4 UUID (version nibble 4, variant 8/9/a/b).
const dummy = "a1b2c3d4-e5f6-4a89-9bcd-ef0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.PingIdentity {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		// --- true positives (still detected) ---
		{
			name: "client_secret assignment",
			body: "pingone config\nclient_secret=" + dummy,
			want: 1,
		},
		{
			name: "worker_secret yaml",
			body: "# pingidentity worker app\nworker_secret: \"" + dummy + "\"",
			want: 1,
		},
		{
			name: "pingone_secret env",
			body: "PINGONE_SECRET=" + dummy,
			want: 1,
		},

		// --- false positives (now suppressed) ---
		{
			name: "environment_id lookalike",
			body: "pingone environment_id: " + dummy,
			want: 0,
		},
		{
			name: "correlation header",
			body: "X-PingOne-Correlation-Id: " + dummy,
			want: 0,
		},
		{
			name: "kubernetes resource uid",
			body: "# pingidentity helm chart\n  uid: " + dummy,
			want: 0,
		},
		{
			name: "request trace id",
			body: "2024 pingone request trace_id=" + dummy,
			want: 0,
		},
		{
			name: "app_id lookalike",
			body: "pingone app_id=" + dummy,
			want: 0,
		},
		{
			name: "no secret keyword",
			body: "pingone foo=" + dummy,
			want: 0,
		},
		{
			name: "bare ping mention",
			body: "# ping latency\nX=" + dummy,
			want: 0,
		},
		{
			name: "sequential placeholder uuid",
			body: "client_secret=00000000-0000-4000-8000-000000000000",
			want: 0,
		},
		{
			name: "non-v4 uuid rejected by regex",
			body: "client_secret=a1b2c3d4-e5f6-1a89-7bcd-ef0123456789",
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scanner{}.FromData(context.Background(), false, []byte(tc.body))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(res) != tc.want {
				t.Fatalf("got %d results, want %d", len(res), tc.want)
			}
		})
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("client_secret=" + dummy + "\nclient_secret=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if got := redact(dummy); got != dummy[:8]+"..." {
		t.Fatalf("redact mismatch: %s", got)
	}
}
