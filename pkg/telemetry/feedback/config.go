package feedback

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// DefaultEndpoint is the relay that receives user feedback. The crash relay
// and the feedback relay are separate so feedback never rides an opt-in the
// operator granted for crashes.
const DefaultEndpoint = "https://feedback.plenoai.com/v1/pleno-dlp"

// EnvEndpoint overrides the feedback endpoint.
const EnvEndpoint = "PLENO_DLP_FEEDBACK_ENDPOINT"

// SpoolDir is where feedback reports are written:
// <telemetry root>/feedback.
func SpoolDir(getenv func(string) string) (string, error) {
	dir, err := crash.Dir(getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "feedback"), nil
}

// Endpoint resolves the feedback relay. Precedence: env, telemetry.json,
// default. Plain http is allowed only for loopback hosts.
func Endpoint(getenv func(string) string) (string, error) {
	ep := DefaultEndpoint
	dir, err := crash.Dir(getenv)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "telemetry.json")
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var fc struct {
			FeedbackEndpoint string `json:"feedback_endpoint"`
		}
		if err := json.Unmarshal(b, &fc); err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		if fc.FeedbackEndpoint != "" {
			ep = fc.FeedbackEndpoint
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return "", err
	}
	if e := getenv(EnvEndpoint); e != "" {
		ep = e
	}
	if err := crash.ValidateEndpoint(ep); err != nil {
		return "", err
	}
	return ep, nil
}
