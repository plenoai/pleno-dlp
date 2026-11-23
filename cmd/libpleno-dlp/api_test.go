package main

import (
	"encoding/json"
	"testing"
)

type env struct {
	OK    json.RawMessage `json:"ok"`
	Error *apiError       `json:"error"`
}

func parse(t *testing.T, b []byte) env {
	t.Helper()
	var e env
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("invalid envelope %s: %v", b, err)
	}
	return e
}

func TestEnvelope(t *testing.T) {
	if e := parse(t, scanBytes([]byte("nothing here"), "")); e.Error != nil || string(e.OK) != "[]" {
		t.Fatalf("empty scan must be ok:[] got %+v", e)
	}
	if e := parse(t, scanBytes([]byte("https://hooks.slack.com/services/"+"T024BE7LD/B024BE7LD/abcdefghijklmnopqrstuvwx"), `{"include_raw":false}`)); e.Error != nil || len(e.OK) < 10 {
		t.Fatalf("scan: %s", e.OK)
	}
	for name, tc := range map[string]struct {
		got  []byte
		code string
	}{
		"bad opts":     {scanBytes(nil, "{"), "invalid_argument"},
		"empty paths":  {scanPaths("[]", ""), "invalid_argument"},
		"unknown":      {verify("NoSuch", "x"), "unknown_detector"},
		"unconfirmed":  {revoke("GitHub", "x", ""), "not_confirmed"},
		"missing path": {scanPaths(`["/nonexistent/pleno"]`, ""), "internal"},
	} {
		e := parse(t, tc.got)
		if e.Error == nil || e.Error.Code != tc.code {
			t.Errorf("%s: want code %s, got %+v", name, tc.code, e.Error)
		}
	}
	if e := parse(t, revoke("GitHub", "x", `{"dry_run":true}`)); e.Error != nil {
		t.Fatalf("dry run: %+v", e.Error)
	}
	if e := parse(t, version()); string(e.OK) != `"1.1.0"` {
		t.Fatalf("version %s", e.OK)
	}
	if e := parse(t, listDetectors()); e.Error != nil || len(e.OK) < 1000 {
		t.Fatal("detectors")
	}
}
