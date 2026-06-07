package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   string
	}{
		{name: "empty", secret: "", want: "***"},
		{name: "len8_at_boundary", secret: "abcdefgh", want: "***"},
		{name: "len9_just_over", secret: "abcdefghi", want: "abcdefgh..."},
		{
			name:   "long",
			secret: "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			want:   "ghp_0123...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSecret(tt.secret)
			if got != tt.want {
				t.Errorf("redactSecret(<secret len=%d>) = %q, want %q",
					len(tt.secret), got, tt.want)
			}
			if len(tt.secret) > 8 && got == tt.secret {
				t.Errorf("redactSecret leaked full secret (len=%d)", len(tt.secret))
			}
		})
	}
}

func TestResolveSecret(t *testing.T) {
	t.Run("raw_passthrough_trims", func(t *testing.T) {
		cmd := &cobra.Command{}
		got, err := resolveSecret(cmd, "  ghp_token  ")
		if err != nil {
			t.Fatalf("resolveSecret returned error: %v", err)
		}
		if got != "ghp_token" {
			t.Errorf("resolveSecret(raw) = %q, want %q", got, "ghp_token")
		}
	})

	t.Run("stdin_dash_trims_trailing_newline", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.SetIn(bytes.NewBufferString("ghp_fromstdin\n"))
		got, err := resolveSecret(cmd, "-")
		if err != nil {
			t.Fatalf("resolveSecret returned error: %v", err)
		}
		if got != "ghp_fromstdin" {
			t.Errorf("resolveSecret(stdin) = %q, want %q", got, "ghp_fromstdin")
		}
	})

	t.Run("stdin_at_limit_accepted", func(t *testing.T) {
		const maxSecretBytes = 1024
		payload := strings.Repeat("a", maxSecretBytes)
		cmd := &cobra.Command{}
		cmd.SetIn(bytes.NewBufferString(payload))
		got, err := resolveSecret(cmd, "-")
		if err != nil {
			t.Fatalf("resolveSecret at limit returned error: %v", err)
		}
		if len(got) != maxSecretBytes {
			t.Errorf("resolveSecret at-limit len = %d, want %d", len(got), maxSecretBytes)
		}
	})

	t.Run("stdin_over_limit_rejected", func(t *testing.T) {
		const maxSecretBytes = 1024
		payload := strings.Repeat("a", maxSecretBytes+1)
		cmd := &cobra.Command{}
		cmd.SetIn(bytes.NewBufferString(payload))
		_, err := resolveSecret(cmd, "-")
		if err == nil {
			t.Fatal("resolveSecret over-limit: expected error, got nil")
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("resolveSecret over-limit error = %q, want it to mention %q",
				err.Error(), "exceeds")
		}
	})
}

func TestIsInteractiveStdin(t *testing.T) {
	if isInteractiveStdin(bytes.NewBufferString("anything")) {
		t.Error("isInteractiveStdin(bytes.Buffer) = true, want false")
	}
}
