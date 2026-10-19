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
	if len(body) > MaxReportBytes {
		return fmt.Errorf("crash report is %d bytes, exceeds %d", len(body), MaxReportBytes)
	}
	return post(ctx, client, endpoint, version, body)
}

// Post uploads an arbitrary JSON payload with the same transport policy as
// Send: loopback-only plain http, no redirects, one timeout, no retries. It
// lets sibling report kinds (feedback) share one sender instead of cloning
// the transport rules.
func Post(ctx context.Context, client *http.Client, endpoint, version string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(body) > MaxReportBytes {
		return fmt.Errorf("report is %d bytes, exceeds %d", len(body), MaxReportBytes)
	}
	return post(ctx, client, endpoint, version, body)
}

func post(ctx context.Context, client *http.Client, endpoint, version string, body []byte) error {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
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
