// Package feedback sends user-authored feedback to the pleno-dlp relay.
//
// Feedback is deliberately not controlled by the crash-report opt-in: a
// person running `pleno-dlp feedback` has already chosen to send it, so it
// goes out even when crash reports are disabled. It is redacted with the
// same pattern pipeline as crash messages, and the client-side throttle in
// pkg/telemetry/crash caps how many sends leave the machine per hour.
package feedback

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// Schema identifies the feedback wire format. Breaking shape changes bump the
// suffix; the relay rejects schemas it does not know.
const Schema = "pleno-dlp.feedback/v1"

// MaxMessageBytes bounds the redacted message so feedback cannot become a
// bulk upload channel.
const MaxMessageBytes = 4 << 10

// Report is the feedback payload. Fields are an allowlist: anything not
// declared here is never collected.
type Report struct {
	Schema    string    `json:"schema"`
	Version   string    `json:"version"`
	Commit    string    `json:"commit,omitempty"`
	GOOS      string    `json:"goos"`
	GOARCH    string    `json:"goarch"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// Build redacts and stamps a feedback message.
func Build(message, version, commit string, now time.Time) Report {
	red := &crash.Redactor{}
	return Report{
		Schema:    Schema,
		Version:   version,
		Commit:    commit,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Message:   red.Redact(message),
		CreatedAt: now.UTC().Truncate(time.Minute),
	}
}

// Send uploads the feedback payload to the relay.
func Send(ctx context.Context, client *http.Client, endpoint, version string, r Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return crash.Post(ctx, client, endpoint, version, body, 2*MaxMessageBytes)
}
