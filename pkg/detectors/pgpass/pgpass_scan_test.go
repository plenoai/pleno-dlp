package pgpass

import (
	"bytes"
	"context"
	"math/rand"
	"reflect"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func lineByLine(data []byte) []detectors.Result {
	seen := map[string]struct{}{}
	var out []detectors.Result
	for start := 0; start < len(data); {
		line := data[start:]
		if end := bytes.IndexByte(line, '\n'); end >= 0 {
			line = line[:end]
			start += end + 1
		} else {
			start = len(data)
		}
		scanLine(line, seen, &out)
	}
	return detectors.SafeResults(out)
}

// TestFromDataMatchesLineByLine pins the colon-skipping walk to scanning
// every line in order.
func TestFromDataMatchesLineByLine(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	parts := []string{"db.example.com", "5432", "*", "app", "S3cr3tPassw0rd!", "x", ":", ":", "\n", "\n", "# c", "\r"}
	for iter := 0; iter < 5000; iter++ {
		var b []byte
		for k := rng.Intn(30); k > 0; k-- {
			b = append(b, parts[rng.Intn(len(parts))]...)
		}
		if rng.Intn(4) == 0 {
			b = append(b, "\nh.example.org:5432:prod:svc:Zq9vLm2Rt8Kp\n"...)
		}
		got, err := Scanner{}.FromData(context.Background(), false, b)
		if err != nil {
			t.Fatal(err)
		}
		if want := lineByLine(b); !reflect.DeepEqual(got, want) {
			t.Fatalf("%q:\n got %+v\nwant %+v", b, got, want)
		}
	}
}
