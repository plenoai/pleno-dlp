package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SendTimeout bounds one upload; there are no retries.
const SendTimeout = 5 * time.Second

// maxResponseBytes bounds how much of the relay's reply is read.
const maxResponseBytes = 4 << 10

// Receipt is what the relay acknowledged. Issue is the intake issue URL
// when the relay returned one; it points into a private repository.
type Receipt struct {
	Issue string
}

// Send validates the report and POSTs its canonical encoding to endpoint.
// Any 2xx is success.
func Send(ctx context.Context, client *http.Client, endpoint, version string, r Report) (Receipt, error) {
	if err := r.Validate(); err != nil {
		return Receipt{}, err
	}
	body, err := Marshal(r)
	if err != nil {
		return Receipt{}, err
	}
	if len(body) > MaxReportBytes {
		return Receipt{}, fmt.Errorf("report is %d bytes, exceeds %d", len(body), MaxReportBytes)
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return Receipt{}, err
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
		return Receipt{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pleno-dlp/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return Receipt{}, err
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Receipt{}, fmt.Errorf("report relay returned %s", resp.Status)
	}
	return Receipt{Issue: issueURL(reply)}, nil
}

// issueURL extracts {"issue": "<https url>"} from the relay reply. Anything
// else, including control or non-ASCII characters that could drive or spoof
// the terminal, yields "" so a misbehaving relay cannot inject output.
func issueURL(reply []byte) string {
	var v struct {
		Issue string `json:"issue"`
	}
	if json.Unmarshal(reply, &v) != nil || v.Issue == "" {
		return ""
	}
	if strings.IndexFunc(v.Issue, func(c rune) bool { return c < 0x21 || c > 0x7e }) >= 0 {
		return ""
	}
	u, err := url.Parse(v.Issue)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return v.Issue
}
