package slack

import (
	"regexp"
	"sync"
	"testing"
)

func TestTokenRegexConcurrentInitialization(t *testing.T) {
	const workers = 64
	got := make([]*regexp.Regexp, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range got {
		go func(i int) {
			defer wg.Done()
			got[i] = tokenRe()
		}(i)
	}
	wg.Wait()
	if got[0] == nil {
		t.Fatal("lazy token regex returned nil")
	}
	for i := 1; i < len(got); i++ {
		if got[i] != got[0] {
			t.Fatalf("worker %d received a different compiled regex", i)
		}
	}
	if got[0].FindString("xoxb-1-2-abcdefghijklmnopqrstuvwxyz") == "" {
		t.Fatal("compiled token regex did not retain its grammar")
	}
}
