package anonymize

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// analyzeOnce posts text to {baseURL}/api/analyze and decodes findings.
//
// Decoupled from Supervisor so it can be unit-tested against a
// httptest.Server without lifecycle entanglement, and so Supervisor's
// shutdown logic doesn't have to know the wire format. The caller is
// responsible for picking up errors and matching them against the
// sentinel set in types.go.
func analyzeOnce(ctx context.Context, hc *http.Client, baseURL, text, language string) ([]Finding, error) {
	body, err := json.Marshal(analyzeRequest{
		Text:     text,
		Language: language,
	})
	if err != nil {
		// json.Marshal of a struct with only string/[]string fields
		// can only fail under absurd circumstances (unsupported
		// type via reflection); we still return the error so a
		// future change to analyzeRequest doesn't silently swallow.
		return nil, fmt.Errorf("anonymize: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("anonymize: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		// Context cancellation (scan aborted) and connection refused
		// (engine died mid-scan) both arrive here. The engine wiring
		// layer surfaces these per-call rather than tearing down the
		// supervisor — a transient blip on one chunk shouldn't cost
		// the whole scan.
		return nil, fmt.Errorf("anonymize: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		// Truncate the body to keep log lines bounded; 512 bytes is
		// enough to surface a Python traceback summary without
		// flooding the log on a misbehaving engine.
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: status=%d body=%q", ErrEngineFailed, resp.StatusCode, string(preview))
	}

	var findings []Finding
	if err := json.NewDecoder(resp.Body).Decode(&findings); err != nil {
		return nil, fmt.Errorf("anonymize: decode response: %w", err)
	}
	return findings, nil
}
