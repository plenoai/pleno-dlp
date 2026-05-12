package openaipf

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
// shutdown logic doesn't have to know the wire format. Callers are
// responsible for matching errors against the sentinel set in types.go.
//
// The wire shape posts {"text": "..."}; language and entities are
// reserved in analyzeRequest but not currently populated by the Go
// side — the wrapper's default behavior (all 8 opf categories, model-
// inferred language) is what scans want. The fields exist so a future
// caller (per-scan language hint, per-detector entity allow-list) can
// add them without breaking the JSON contract.
func analyzeOnce(ctx context.Context, hc *http.Client, baseURL, text string) ([]Finding, error) {
	body, err := json.Marshal(analyzeRequest{Text: text})
	if err != nil {
		// json.Marshal of a struct with only string/[]string fields
		// can only fail under absurd circumstances (unsupported type
		// via reflection); we still return the error so a future
		// change to analyzeRequest doesn't silently swallow.
		return nil, fmt.Errorf("openaipf: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openaipf: build request: %w", err)
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
		return nil, fmt.Errorf("openaipf: do request: %w", err)
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
		return nil, fmt.Errorf("openaipf: decode response: %w", err)
	}
	return findings, nil
}
