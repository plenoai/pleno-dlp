package feedback

import (
	"context"
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// Send POSTs the feedback report to endpoint. The built-in intake receives its
// report/v1 or report/v2 envelope; configured custom relays receive the local
// feedback schema unchanged. Any 2xx is success.
func Send(ctx context.Context, client *http.Client, endpoint, version string, r Report) error {
	var payload any = r
	if usesIntakeProtocol(endpoint) {
		intake, err := intakeReportFor(r)
		if err != nil {
			return err
		}
		payload = intake
	}
	return crash.Post(ctx, client, endpoint, version, payload)
}
