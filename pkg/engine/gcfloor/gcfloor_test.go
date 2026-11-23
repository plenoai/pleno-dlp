package gcfloor

import "testing"

func TestPercent(t *testing.T) {
	for _, tc := range []struct {
		live uint64
		want int
	}{
		{0, 100},
		{1, maxPercent},
		{4 << 20, 6300},
		{64 << 20, 300},
		{100 << 20, 100}, // floor/live rounds down to 2
		{Floor / 2, 100},
		{Floor, 100},
		{8 << 30, 100},
	} {
		if got := Percent(tc.live); got != tc.want {
			t.Errorf("Percent(%d) = %d, want %d", tc.live, got, tc.want)
		}
	}
	// The goal live*(1+p/100) never exceeds the floor while it applies.
	for live := uint64(1 << 20); live*2 < Floor; live += 1 << 20 {
		if p := Percent(live); live*uint64(100+p)/100 > Floor {
			t.Fatalf("live %d: goal %d above floor", live, live*uint64(100+p)/100)
		}
	}
}
