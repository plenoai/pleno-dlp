package feedback

import (
	"context"
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// Send POSTs the feedback report to endpoint. Any 2xx is success. It shares
// the crash relay's transport policy.
func Send(ctx context.Context, client *http.Client, endpoint, version string, r Report) error {
	return crash.Post(ctx, client, endpoint, version, r)
}
