package detectors

import (
	"bytes"
	"context"
	"errors"
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
	err := ForEachReaderLineSubmatch(context.Background(), bytes.NewReader([]byte("secret=x\n")), 64, re, []byte("="), 1, 0, []int{1}, func([][]byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected short ReaderAt to fail closed")
	}
}

func TestForEachReaderLineSubmatchHonorsMaxOccurrences(t *testing.T) {
	re := regexp.MustCompile(`(?m)^([^\n]+)$`)
	data := []byte("one:two:three:four:five\none:two:three:four:five:six\n")
	var got []string
	err := ForEachReaderLineSubmatch(context.Background(), bytes.NewReader(data), int64(len(data)), re, []byte(":"), 4, 4, []int{1}, func(groups [][]byte) error {
		got = append(got, string(groups[0]))
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "one:two:three:four:five" {
		t.Fatalf("matches = %q, want exactly the four-colon line", got)
	}
}

func TestForEachReaderLineSubmatchZeroMaxKeepsLowerBoundOnly(t *testing.T) {
	re := regexp.MustCompile(`(?m)^([^\n]+)$`)
	data := []byte("one:two:three:four:five\n")
	called := false
	err := ForEachReaderLineSubmatch(context.Background(), bytes.NewReader(data), int64(len(data)), re, []byte(":"), 4, 0, []int{1}, func([][]byte) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("zero maxOccurrences should preserve the lower-bound-only behavior")
	}
}

func TestForEachReaderLineSubmatchPropagatesCancellation(t *testing.T) {
	re := regexp.MustCompile(`(?m)^([^\n]+)$`)
	data := []byte("one:two:three:four\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ForEachReaderLineSubmatch(ctx, bytes.NewReader(data), int64(len(data)), re, []byte(":"), 4, 4, []int{1}, func([][]byte) error {
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
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
