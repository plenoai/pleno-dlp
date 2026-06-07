package s3

import (
	"context"
	"encoding/json"
	"testing"

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
