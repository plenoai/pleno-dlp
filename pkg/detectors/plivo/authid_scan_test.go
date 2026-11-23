package plivo

import (
	"math/rand"
	"reflect"
	"testing"
)

// TestFindAuthIDsMatchesRegexp pins the byte scanner to authIDRe.
func TestFindAuthIDsMatchesRegexp(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	alphabet := []byte("MASAMXZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_a -\n.é")
	for i := 0; i < 20000; i++ {
		n := rng.Intn(90)
		data := make([]byte, 0, n)
		for len(data) < n {
			if rng.Intn(15) == 0 {
				data = append(data, []byte([]string{"MA", "SA"}[rng.Intn(2)])...)
				for k := 0; k < 18; k++ {
					data = append(data, "0123456789ABCDEFXYZ"[rng.Intn(19)])
				}
				continue
			}
			data = append(data, alphabet[rng.Intn(len(alphabet))])
		}
		var want [][]byte
		for _, m := range authIDRe().FindAllSubmatch(data, -1) {
			want = append(want, m[1])
		}
		if got := findAuthIDs(data); !reflect.DeepEqual(want, got) {
			t.Fatalf("%q: want %q got %q", data, want, got)
		}
	}
}
