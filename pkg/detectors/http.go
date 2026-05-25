package detectors

import (
	"fmt"
	"net/http"
)

// ClassifyVerifyHTTP normalises an HTTP verification response into a
// (verified, err) pair that distinguishes transient failures from explicit
// rejections.
//
//   - Transport error (resp == nil)     → (false, err)            // network / TLS failure
//   - resp.StatusCode in acceptCodes    → (true,  nil)            // valid credential
//   - resp.StatusCode in rejectCodes    → (false, nil)            // explicit rejection
//   - resp.StatusCode >= 500            → (false, fmt.Errorf(…))  // provider-side transient
//   - resp.StatusCode == 429            → (false, fmt.Errorf(…))  // rate-limit transient
//   - anything else                     → (false, nil)            // treat as rejection
//
// acceptCodes must include every status code that means "credential is valid"
// (commonly []int{200}). rejectCodes lists statuses that are unambiguously
// invalid (commonly []int{401, 403, 404}); any status not in either list and
// not a transient code is also treated as rejection so callers don't need to
// be exhaustive.
//
// Callers pass transportErr from http.Client.Do. When transportErr != nil the
// resp argument is unused and may be nil.
func ClassifyVerifyHTTP(resp *http.Response, transportErr error, acceptCodes, rejectCodes []int) (bool, error) {
	if transportErr != nil {
		return false, transportErr
	}
	code := resp.StatusCode
	for _, c := range acceptCodes {
		if code == c {
			return true, nil
		}
	}
	if isTransient(code) {
		return false, fmt.Errorf("verify: transient HTTP %d", code)
	}
	return false, nil
}

// isTransient reports whether an HTTP status code represents a condition that
// is temporary and not an authoritative "invalid credential" verdict from the
// provider. Callers should propagate these as errors so the engine can mark
// the finding "verification failed" rather than "verified-not-valid".
func isTransient(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}
