package gcs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestType(t *testing.T) {
	s := &Source{}
	if s.Type() != sources.SourceGCS {
		t.Fatalf("got %v, want SourceGCS", s.Type())
	}
}

func TestInitMissingBucket(t *testing.T) {
	s := &Source{}
	cfg, _ := json.Marshal(Config{})
	err := s.Init(context.Background(), "test", 0, 0, false, cfg, 1)
	if err == nil {
		t.Fatal("expected error for missing bucket")
	}
}

func TestInitBadJSON(t *testing.T) {
	s := &Source{}
	err := s.Init(context.Background(), "test", 0, 0, false, []byte("{broken"), 1)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestInitBadGlob(t *testing.T) {
	s := &Source{}
	cfg, _ := json.Marshal(Config{
		Bucket:  "test-bucket",
		Include: []string{"[invalid"},
	})
	err := s.Init(context.Background(), "test", 0, 0, false, cfg, 1)
	if err == nil {
		t.Fatal("expected error for invalid glob")
	}
}

func TestKeyAllowed(t *testing.T) {
	tests := []struct {
		name    string
		include []string
		exclude []string
		key     string
		want    bool
	}{
		{"no filters", nil, nil, "foo/bar.txt", true},
		{"include match", []string{"*.txt"}, nil, "foo/bar.txt", true},
		{"include no match", []string{"*.go"}, nil, "foo/bar.txt", false},
		{"exclude match", nil, []string{"*.log"}, "foo/bar.log", false},
		{"exclude trumps include", []string{"*"}, []string{"*.log"}, "foo/bar.log", false},
		{"path glob exclude", nil, []string{"secret/*"}, "secret/key.pem", false},
		{"basename exclude", nil, []string{"*.pem"}, "secret/key.pem", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Source{include: tt.include, exclude: tt.exclude}
			if got := s.keyAllowed(tt.key); got != tt.want {
				t.Errorf("keyAllowed(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("hello world")) {
		t.Error("text classified as binary")
	}
	if !isBinary([]byte{0x00, 0x01, 0x02}) {
		t.Error("binary not detected")
	}
}

func TestRegistered(t *testing.T) {
	src := sources.New(sources.SourceGCS)
	if src == nil {
		t.Fatal("GCS source not registered")
	}
	if src.Type() != sources.SourceGCS {
		t.Fatalf("got %v, want SourceGCS", src.Type())
	}
}

func TestIncrementalStateSkipsUnchangedObject(t *testing.T) {
	s := &Source{}
	previous := []byte(`{"version":1,"objects":{"configs/app.yml":{"generation":1234567890,"etag":"abc","size":512,"updated":"2026-06-09T00:00:00Z"}}}`)
	if err := s.SetIncrementalState(previous); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}

	unchanged := objectIncrementalState{Generation: 1234567890, ETag: "abc", Size: 512, Updated: "2026-06-09T00:00:00Z"}
	if !s.objectUnchanged("configs/app.yml", unchanged) {
		t.Fatal("unchanged object should be skipped")
	}
	changed := objectIncrementalState{Generation: 9999999999, ETag: "def", Size: 512, Updated: "2026-06-10T00:00:00Z"}
	if s.objectUnchanged("configs/app.yml", changed) {
		t.Fatal("changed object must not be skipped")
	}
	if s.objectUnchanged("new.txt", unchanged) {
		t.Fatal("new object must not be skipped")
	}
}

func TestIncrementalStateRoundTrip(t *testing.T) {
	state := objectIncrementalState{
		Generation: 1234567890,
		ETag:       "etag-abc",
		Size:       1024,
		Updated:    "2026-06-09T00:00:00Z",
	}
	s := &Source{nextState: &incrementalState{
		Version: 1,
		Objects: map[string]objectIncrementalState{
			"configs/app.yml": state,
		},
	}}
	raw := s.IncrementalState()
	if len(raw) == 0 {
		t.Fatal("IncrementalState must not be empty")
	}

	var decoded incrementalState
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode IncrementalState: %v", err)
	}
	if decoded.Objects["configs/app.yml"] != state {
		t.Fatalf("decoded state = %#v, want %#v", decoded.Objects["configs/app.yml"], state)
	}
}

func TestIncrementalStateEmpty(t *testing.T) {
	s := &Source{}
	if err := s.SetIncrementalState(nil); err != nil {
		t.Fatalf("SetIncrementalState(nil): %v", err)
	}
	if s.hasPreviousState {
		t.Fatal("should not have previous state")
	}
	if raw := s.IncrementalState(); raw != nil {
		t.Fatalf("IncrementalState should be nil before Chunks, got %s", raw)
	}
}
