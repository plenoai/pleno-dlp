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

func TestForEachReaderLineSubmatchFuncDefersAndCachesFactory(t *testing.T) {
	re := regexp.MustCompile(`(?m)^([^\n]+)$`)
	tests := []struct {
		name       string
		data       []byte
		size       int64
		needle     []byte
		min        int
		max        int
		nilFactory bool
		nilResult  bool
		cancelled  bool
		wantCalls  int
		wantVisits int
		wantErr    bool
	}{
		{
			name:   "rejected lines do not build regexp",
			data:   []byte("noise\nwithout marker\n"),
			size:   int64(len("noise\nwithout marker\n")),
			needle: []byte(":"),
			min:    1,
		},
		{
			name:    "reader error does not build regexp",
			data:    []byte("noise\n"),
			size:    int64(len("noise\n")) + 1,
			needle:  []byte(":"),
			min:     1,
			wantErr: true,
		},
		{
			name:       "nil factory is rejected",
			needle:     []byte(":"),
			min:        1,
			nilFactory: true,
			wantErr:    true,
		},
		{
			name:      "nil regexp is rejected on candidate",
			data:      []byte("one:two"),
			size:      int64(len("one:two")),
			needle:    []byte(":"),
			min:       1,
			nilResult: true,
			wantCalls: 1,
			wantErr:   true,
		},
		{
			name:      "cancellation does not build regexp",
			data:      []byte("one:two\n"),
			size:      int64(len("one:two\n")),
			needle:    []byte(":"),
			min:       1,
			cancelled: true,
			wantErr:   true,
		},
		{
			name:       "multiple matches and eof share one regexp",
			data:       []byte("one:two\nthree:four\nfive:six"),
			size:       int64(len("one:two\nthree:four\nfive:six")),
			needle:     []byte(":"),
			min:        1,
			wantCalls:  1,
			wantVisits: 3,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			visits := 0
			ctx := context.Background()
			if tt.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var factory func() *regexp.Regexp
			if !tt.nilFactory {
				factory = func() *regexp.Regexp {
					calls++
					if tt.nilResult {
						return nil
					}
					return re
				}
			}
			err := ForEachReaderLineSubmatchFunc(ctx, bytes.NewReader(tt.data), tt.size, factory, tt.needle, tt.min, tt.max, []int{1}, func([][]byte) error {
				visits++
				return nil
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr=%v", err, tt.wantErr)
			}
			if calls != tt.wantCalls {
				t.Fatalf("factory calls = %d, want %d", calls, tt.wantCalls)
			}
			if visits != tt.wantVisits {
				t.Fatalf("visits = %d, want %d", visits, tt.wantVisits)
			}
		})
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
