package crash

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestThrottleCorruptStateFailsOpen(t *testing.T) {
	for _, kind := range []string{"crash", "feedback"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, throttleFile)
			if err := os.WriteFile(path, []byte("invalid json"), 0o600); err != nil {
				t.Fatal(err)
			}
			th := &Throttle{Dir: dir}
			var ok bool
			var err error
			if kind == "crash" {
				ok, err = th.AllowCrash("fp")
			} else {
				ok, err = th.AllowFeedback()
			}
			if err != nil || !ok {
				t.Fatalf("corrupt state blocked upload: %v, %v", ok, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("state permissions: %v, %v", info, err)
			}
		})
	}
}

func TestThrottleWriteFailureAllowsUpload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	th := &Throttle{Dir: path}
	if ok, err := th.AllowCrash("fp"); !ok || err == nil {
		t.Fatalf("write failure: %v, %v", ok, err)
	}
	if ok, err := th.AllowFeedback(); !ok || err == nil {
		t.Fatalf("write failure: %v, %v", ok, err)
	}
}

func TestThrottleCrashOnePerFingerprintPerHour(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	th := &Throttle{Dir: dir, Now: func() time.Time { return now }}

	if ok, err := th.AllowCrash("abc"); err != nil || !ok {
		t.Fatalf("first send: ok=%v err=%v", ok, err)
	}
	if ok, err := th.AllowCrash("abc"); err != nil || ok {
		t.Fatalf("second send within the hour: ok=%v err=%v", ok, err)
	}
	if ok, _ := th.AllowCrash("other"); !ok {
		t.Fatal("a different fingerprint must not be throttled by another's send")
	}

	now = now.Add(CrashSendInterval)
	if ok, err := th.AllowCrash("abc"); err != nil || !ok {
		t.Fatalf("after interval: ok=%v err=%v", ok, err)
	}
}

func TestThrottleFeedbackWindow(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	th := &Throttle{Dir: dir, Now: func() time.Time { return now }}

	for i := 0; i < FeedbackSendLimit; i++ {
		if ok, err := th.AllowFeedback(); err != nil || !ok {
			t.Fatalf("send %d: ok=%v err=%v", i, ok, err)
		}
	}
	if ok, err := th.AllowFeedback(); err != nil || ok {
		t.Fatalf("over limit: ok=%v err=%v", ok, err)
	}

	now = now.Add(FeedbackSendWindow)
	if ok, err := th.AllowFeedback(); err != nil || !ok {
		t.Fatalf("after window: ok=%v err=%v", ok, err)
	}
}

func TestThrottlePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	first := &Throttle{Dir: dir, Now: clock}
	if ok, _ := first.AllowCrash("fp"); !ok {
		t.Fatal("first instance send")
	}
	second := &Throttle{Dir: dir, Now: clock}
	if ok, _ := second.AllowCrash("fp"); ok {
		t.Fatal("a new process (instance) must see the recorded send")
	}
}

func TestThrottleZeroDirAllowsEverything(t *testing.T) {
	th := &Throttle{}
	for i := 0; i < FeedbackSendLimit+2; i++ {
		if ok, err := th.AllowFeedback(); err != nil || !ok {
			t.Fatalf("zero-dir feedback %d: ok=%v err=%v", i, ok, err)
		}
	}
	if ok, _ := th.AllowCrash("fp"); !ok {
		t.Fatal("zero-dir crash send throttled")
	}
}

func TestThrottleOverrides(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	th := &Throttle{Dir: dir, Now: func() time.Time { return now }, FeedbackLimit: 1, FeedbackWindow: time.Minute}
	if ok, _ := th.AllowFeedback(); !ok {
		t.Fatal("first")
	}
	if ok, _ := th.AllowFeedback(); ok {
		t.Fatal("override limit ignored")
	}
	now = now.Add(time.Minute)
	if ok, _ := th.AllowFeedback(); !ok {
		t.Fatal("override window ignored")
	}
}
