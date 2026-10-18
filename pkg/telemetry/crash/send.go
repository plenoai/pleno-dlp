package crash

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SendTimeout bounds one upload; there are no retries.
const SendTimeout = 5 * time.Second

// Send POSTs the report to endpoint. Any 2xx is success.
func Send(ctx context.Context, client *http.Client, endpoint, version string, r Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return Post(ctx, client, endpoint, version, body, MaxReportBytes)
}

// Post uploads an already-serialized telemetry payload to endpoint. Any 2xx
// is success. It is the shared transport for crash reports and feedback.
func Post(ctx context.Context, client *http.Client, endpoint, version string, payload []byte, maxBytes int) error {
	if len(payload) > maxBytes {
		return fmt.Errorf("telemetry payload is %d bytes, exceeds %d", len(payload), maxBytes)
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return err
	}
	if client == nil {
		client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pleno-dlp/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("crash relay returned %s", resp.Status)
	}
	return nil
}
