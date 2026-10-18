package crash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const (
	// CrashSendInterval is the minimum spacing between automatic uploads of
	// reports that share a fingerprint.
	CrashSendInterval = time.Hour
	// FeedbackSendLimit is the maximum number of feedback uploads allowed per
	// FeedbackSendWindow.
	FeedbackSendLimit = 5
	// FeedbackSendWindow is the window FeedbackSendLimit applies over.
	FeedbackSendWindow = time.Hour
	// throttleFile is the throttle state file under the telemetry root. It
	// lives beside crash/ rather than inside it so spool pruning never
	// deletes it.
	throttleFile = "throttle.json"
)

// Throttle is the client's own, best-effort rate limiter for telemetry
// uploads. The relay enforces the authoritative per-address limit; this only
// stops a local crash loop or a scripted `feedback --yes` from hammering it.
// A zero Dir disables throttling, and an unreadable/corrupt state file fails
// open so a broken throttle never blocks an upload.
type Throttle struct {
	// Dir is the telemetry root holding throttle.json.
	Dir string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// FeedbackLimit and FeedbackWindow override the package defaults when
	// positive. Tests use them to avoid real-time waits.
	FeedbackLimit  int
	FeedbackWindow time.Duration
}

// throttleState is the persisted per-fingerprint and feedback history.
type throttleState struct {
	Crashes  map[string]time.Time `json:"crashes,omitempty"`
	Feedback []time.Time          `json:"feedback,omitempty"`
}

func (t *Throttle) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Throttle) feedbackLimit() int {
	if t.FeedbackLimit > 0 {
		return t.FeedbackLimit
	}
	return FeedbackSendLimit
}

func (t *Throttle) feedbackWindow() time.Duration {
	if t.FeedbackWindow > 0 {
		return t.FeedbackWindow
	}
	return FeedbackSendWindow
}

// AllowCrash reports whether a report with this fingerprint may be uploaded
// now and, when it may, records the send. At most one send per fingerprint
// per CrashSendInterval.
func (t *Throttle) AllowCrash(fingerprint string) (bool, error) {
	if t.Dir == "" {
		return true, nil
	}
	now := t.now()
	s := t.load()
	for fp, ts := range s.Crashes {
		if now.Sub(ts) >= CrashSendInterval {
			delete(s.Crashes, fp)
		}
	}
	if last, ok := s.Crashes[fingerprint]; ok && now.Sub(last) < CrashSendInterval {
		return false, nil
	}
	if s.Crashes == nil {
		s.Crashes = map[string]time.Time{}
	}
	s.Crashes[fingerprint] = now
	return true, t.save(s)
}

// AllowFeedback reports whether a feedback upload may be sent now and, when
// it may, records the send. At most feedbackLimit sends per feedbackWindow.
func (t *Throttle) AllowFeedback() (bool, error) {
	if t.Dir == "" {
		return true, nil
	}
	now := t.now()
	window := t.feedbackWindow()
	s := t.load()
	kept := s.Feedback[:0]
	for _, ts := range s.Feedback {
		if now.Sub(ts) < window {
			kept = append(kept, ts)
		}
	}
	s.Feedback = kept
	if len(s.Feedback) >= t.feedbackLimit() {
		return false, nil
	}
	s.Feedback = append(s.Feedback, now)
	return true, t.save(s)
}

// load reads the throttle state, treating any error as empty state (fail open).
func (t *Throttle) load() throttleState {
	var s throttleState
	b, err := os.ReadFile(filepath.Join(t.Dir, throttleFile))
	if err != nil || len(b) == 0 {
		return throttleState{}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return throttleState{}
	}
	return s
}

// save persists the throttle state atomically and privately.
func (t *Throttle) save(s throttleState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writePrivate(t.Dir, filepath.Join(t.Dir, throttleFile), append(b, '\n'))
}
