package detectors

import (
	"bytes"
	"context"
	"regexp"
	"testing"
)

func TestForEachReaderPrefixedSubmatchRejectsShortReader(t *testing.T) {
	re := regexp.MustCompile(`secret=([[:alnum:]]+)`)
	err := ForEachReaderPrefixedSubmatch(context.Background(), bytes.NewReader([]byte("secret=x")), 64, re, []byte("secret="), []int{1}, func([][]byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected short ReaderAt to fail closed")
	}
}

func TestForEachReaderLineSubmatchRejectsShortReader(t *testing.T) {
	re := regexp.MustCompile(`(?m)^secret=([[:alnum:]]+)$`)
	err := ForEachReaderLineSubmatch(context.Background(), bytes.NewReader([]byte("secret=x\n")), 64, re, []byte("="), 1, []int{1}, func([][]byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected short ReaderAt to fail closed")
	}
}

func TestForEachReaderPrefixedSubmatchCopiesOnlyCapture(t *testing.T) {
	re := regexp.MustCompile(`TOKEN=([[:alnum:]]+)`)
	var got []byte
	err := ForEachReaderPrefixedSubmatch(context.Background(), bytes.NewReader([]byte("prefix TOKEN=abc suffix")), 23, re, []byte("TOKEN="), []int{1}, func(groups [][]byte) error {
		got = groups[0]
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("capture = %q, want abc", got)
	}
}
