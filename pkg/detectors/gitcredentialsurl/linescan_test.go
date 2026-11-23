package gitcredentialsurl

import (
	"context"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// referenceFromData is the pre-optimization line loop (every line through
// lineRe); FromData must return identical results.
func referenceFromData(data []byte) []detectors.Result {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result
	for start := 0; start < len(str); {
		line := str[start:]
		if end := strings.IndexByte(line, '\n'); end >= 0 {
			line = line[:end]
			start += end + 1
		} else {
			start = len(str)
		}
		scanLine([]byte(line), seen, &out)
	}
	return detectors.SafeResults(out)
}

func TestFromDataMatchesLineReference(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	pieces := []string{"https://", "ftp://", "http://", "://", "user", ":", "p4ssw0rdX9", "@", "git.example.com", "/repo.git", " ", "\t", "\n", "\r\n", "x", "{{tok}}"}
	nonEmpty := 0
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := 0; j < rng.Intn(16); j++ {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		data := []byte(b.String())
		want := referenceFromData(data)
		got, err := Scanner{}.FromData(context.Background(), false, data)
		if err != nil {
			t.Fatal(err)
		}
		if len(want) > 0 {
			nonEmpty++
		}
		if !reflect.DeepEqual(want, got) && !(len(want) == 0 && len(got) == 0) {
			t.Fatalf("%q:\nwant %+v\ngot  %+v", data, want, got)
		}
	}
	if nonEmpty == 0 {
		t.Fatal("no positive inputs generated")
	}
}
