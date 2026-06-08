package s3

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestType(t *testing.T) {
	s := &Source{}
	if s.Type() != sources.SourceS3 {
		t.Fatalf("got %v, want SourceS3", s.Type())
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

func TestInitBadJSON(t *testing.T) {
	s := &Source{}
	err := s.Init(context.Background(), "test", 0, 0, false, []byte("{broken"), 1)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
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
	src := sources.New(sources.SourceS3)
	if src == nil {
		t.Fatal("S3 source not registered")
	}
	if src.Type() != sources.SourceS3 {
		t.Fatalf("got %v, want SourceS3", src.Type())
	}
}

func TestIncrementalStateSkipsUnchangedObject(t *testing.T) {
	s := &Source{}
	previous := []byte(`{"version":1,"objects":{"a.txt":{"etag":"\"abc\"","size":12,"last_modified":"2026-06-09T00:00:00Z"}}}`)
	if err := s.SetIncrementalState(previous); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}

	unchanged := objectIncrementalState{ETag: `"abc"`, Size: 12, LastModified: "2026-06-09T00:00:00Z"}
	if !s.objectUnchanged("a.txt", unchanged) {
		t.Fatal("unchanged object should be skipped")
	}
	changed := objectIncrementalState{ETag: `"def"`, Size: 12, LastModified: "2026-06-09T00:00:00Z"}
	if s.objectUnchanged("a.txt", changed) {
		t.Fatal("changed object must not be skipped")
	}
	if s.objectUnchanged("new.txt", unchanged) {
		t.Fatal("new object must not be skipped")
	}
}

func TestIncrementalStateRoundTrip(t *testing.T) {
	modified := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	state := stateForObject(types.Object{
		Key:          aws.String("a.txt"),
		ETag:         aws.String(`"abc"`),
		Size:         aws.Int64(12),
		LastModified: aws.Time(modified),
	})
	if got, want := state.LastModified, "2026-06-09T00:00:00Z"; got != want {
		t.Fatalf("LastModified = %q, want %q", got, want)
	}

	s := &Source{nextState: &incrementalState{
		Version: 1,
		Objects: map[string]objectIncrementalState{
			"a.txt": state,
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
	if decoded.Objects["a.txt"] != state {
		t.Fatalf("decoded state = %#v, want %#v", decoded.Objects["a.txt"], state)
	}
}
