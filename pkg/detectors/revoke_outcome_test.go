package detectors

import "testing"

// TestRevokeResultStatus pins #859: an explicit Outcome wins, and the
// legacy bool maps to confirmed/failed for Revokers that leave it empty.
func TestRevokeResultStatus(t *testing.T) {
	cases := []struct {
		in   RevokeResult
		want RevokeOutcome
	}{
		{RevokeResult{Revoked: true}, RevokeConfirmed},
		{RevokeResult{}, RevokeFailed},
		{RevokeResult{Outcome: RevokeAccepted}, RevokeAccepted},
	}
	for _, c := range cases {
		if got := c.in.Status(); got != c.want {
			t.Errorf("%+v.Status() = %q, want %q", c.in, got, c.want)
		}
	}
}
