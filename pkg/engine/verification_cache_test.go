package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type cacheVerifierDetector struct {
	verifyCalls    atomic.Int64
	verified       bool
	dryVerified    bool
	indeterminate  bool
	verifyMetadata bool
	verifyDelay    time.Duration
	contextual     bool
	rawFromData    bool
	verifyStarted  chan struct{}
	verifyRelease  <-chan struct{}
}

type unmarkedCacheVerifierDetector struct {
	verifyCalls atomic.Int64
	dryCalls    atomic.Int64
}

type conflictingDuplicateVerifierDetector struct {
	verifyCalls atomic.Int64
}

func (*conflictingDuplicateVerifierDetector) Type() detectors.DetectorType {
	return detectors.AWS
}
func (*conflictingDuplicateVerifierDetector) Keywords() []string { return []string{"credential"} }
func (*conflictingDuplicateVerifierDetector) VerificationCacheCanStoreVerdicts() bool {
	return true
}
func (*conflictingDuplicateVerifierDetector) Verify(context.Context, string) (bool, error) {
	return true, nil
}
func (d *conflictingDuplicateVerifierDetector) FromData(_ context.Context, verify bool, _ []byte) ([]detectors.Result, error) {
	results := []detectors.Result{
		{DetectorType: detectors.AWS, Raw: []byte("same-credential")},
		{DetectorType: detectors.AWS, Raw: []byte("same-credential")},
	}
	if verify {
		d.verifyCalls.Add(1)
		results[0].Verified = true
	}
	return results, nil
}

func (*unmarkedCacheVerifierDetector) Type() detectors.DetectorType { return detectors.AWS }
func (*unmarkedCacheVerifierDetector) Keywords() []string           { return []string{"credential"} }
func (*unmarkedCacheVerifierDetector) Verify(context.Context, string) (bool, error) {
	return true, nil
}
func (d *unmarkedCacheVerifierDetector) FromData(_ context.Context, verify bool, _ []byte) ([]detectors.Result, error) {
	if verify {
		d.verifyCalls.Add(1)
	} else {
		d.dryCalls.Add(1)
	}
	return []detectors.Result{{
		DetectorType: detectors.AWS,
		Raw:          []byte("same-credential"),
	}}, nil
}

func (*cacheVerifierDetector) Type() detectors.DetectorType { return detectors.AWS }
func (*cacheVerifierDetector) Keywords() []string           { return []string{"credential"} }
func (d *cacheVerifierDetector) VerificationCacheUsesFullInput() bool {
	return d.contextual
}
func (*cacheVerifierDetector) VerificationCacheCanStoreVerdicts() bool { return true }
func (*cacheVerifierDetector) Verify(context.Context, string) (bool, error) {
	return true, nil
}
func (d *cacheVerifierDetector) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	raw := []byte("same-credential")
	if d.rawFromData {
		raw = append([]byte(nil), data...)
	}
	rawV2 := []byte("pair-a")
	if bytes.Contains(data, []byte("pair-b")) {
		rawV2 = []byte("pair-b")
	}
	result := detectors.Result{
		DetectorType: detectors.AWS,
		Raw:          raw,
		RawV2:        rawV2,
	}
	if !verify && d.dryVerified {
		result.Verified = true
	}
	if verify {
		d.verifyCalls.Add(1)
		if d.verifyStarted != nil {
			select {
			case d.verifyStarted <- struct{}{}:
			default:
			}
		}
		if d.verifyRelease != nil {
			select {
			case <-d.verifyRelease:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if d.verifyDelay > 0 {
			time.Sleep(d.verifyDelay)
		}
		if d.indeterminate {
			result.VerificationErr = errors.New("temporary verification failure")
		} else {
			result.Verified = d.verified
		}
		if d.verifyMetadata {
			result.ExtraData = map[string]string{"verify_skip_reason": "fixture"}
		}
	}
	return []detectors.Result{result}, nil
}

func TestVerificationCacheSkipsRepeatedNegativeVerification(t *testing.T) {
	detector := &cacheVerifierDetector{}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, sink)
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential repeated")},
		{Data: []byte("credential repeated")},
	}}

	stats, err := eng.RunWithStats(context.Background(), src)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 1 {
		t.Fatalf("remote verification calls = %d, want 1", got)
	}
	if stats.VerificationCacheHits != 1 || stats.VerificationCacheMisses != 1 ||
		stats.VerifiedPassesSaved != 1 || stats.VerifiedDetectorCalls != 1 {
		t.Fatalf("cache stats = %+v, want one hit, miss, saved verification, and verified call", stats)
	}
	if stats.VerifiedDetectorCallDuration <= 0 {
		t.Fatalf("verified detector call duration = %s, want positive", stats.VerifiedDetectorCallDuration)
	}
	for i, finding := range sink.Findings() {
		if finding.Result.Verified || finding.Result.VerificationErr != nil {
			t.Fatalf("finding %d verdict = %+v, want provider-confirmed negative", i, finding.Result)
		}
	}
}

func TestVerificationCacheReusesCredentialAcrossIrrelevantContext(t *testing.T) {
	detector := &cacheVerifierDetector{}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential context-a")},
		{Data: []byte("credential context-b")},
	}}

	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 1 {
		t.Fatalf("remote verification calls = %d, want 1", got)
	}
}

func TestVerificationCacheIncludesInputForContextDependentDetector(t *testing.T) {
	detector := &cacheVerifierDetector{contextual: true}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential context-a")},
		{Data: []byte("credential context-b")},
	}}

	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 2 {
		t.Fatalf("remote verification calls = %d, want 2", got)
	}
}

func TestVerificationCacheBypassesUnregisteredDetectorByDefault(t *testing.T) {
	detector := &unmarkedCacheVerifierDetector{}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential context-a")},
		{Data: []byte("credential context-b")},
	}}

	stats, err := eng.RunWithStats(context.Background(), src)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 2 {
		t.Fatalf("remote verification calls = %d, want 2", got)
	}
	if got := detector.dryCalls.Load(); got != 0 {
		t.Fatalf("cache lookup calls = %d, want 0 for an unregistered detector", got)
	}
	if stats.VerificationCacheBypasses != 2 {
		t.Fatalf("cache bypasses = %d, want 2", stats.VerificationCacheBypasses)
	}
}

func TestVerificationCacheBuiltInSafeAllowlist(t *testing.T) {
	want := map[detectors.DetectorType]bool{
		detectors.ArgoCD:          true,
		detectors.BitbucketServer: true,
		detectors.DockerHub:       true,
		detectors.Resend:          true,
		detectors.SlackWebhook:    true,
		detectors.Tailscale:       true,
	}
	eng := NewWithDetectors(detectors.All(), Options{}, &engineRecordingSink{})
	got := make(map[detectors.DetectorType]bool)
	for i, detector := range eng.dets {
		if !eng.verificationCacheable[i] {
			continue
		}
		got[detector.Type()] = true
		if usesData := eng.verificationUsesData[i]; usesData {
			t.Errorf("detector %s uses full input = %v", detector.Type(), usesData)
		}
	}
	for detectorType := range want {
		if !got[detectorType] {
			t.Errorf("audited verdict-cache detector %s is not cacheable", detectorType)
		}
	}
	for detectorType := range got {
		if !want[detectorType] {
			t.Errorf("detector %s entered the verdict cache without an audit", detectorType)
		}
	}
}

func TestVerificationCacheCoalescesConcurrentMisses(t *testing.T) {
	for _, verified := range []bool{false, true} {
		t.Run("verified="+strconv.FormatBool(verified), func(t *testing.T) {
			const workers = 8
			release := make(chan struct{})
			detector := &cacheVerifierDetector{
				verified:      verified,
				verifyStarted: make(chan struct{}, 1),
				verifyRelease: release,
			}
			eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: workers}, &engineRecordingSink{})
			start := make(chan struct{})
			results := make(chan []detectors.Result, workers)
			errs := make(chan error, workers)
			var wg sync.WaitGroup
			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					result, err := eng.fromData(context.Background(), detector, 0, []byte("credential repeated"))
					results <- result
					errs <- err
				}()
			}
			close(start)
			select {
			case <-detector.verifyStarted:
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for the owner verification")
			}
			time.Sleep(20 * time.Millisecond)
			close(release)
			wg.Wait()
			close(results)
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("fromData: %v", err)
				}
			}
			for result := range results {
				if len(result) != 1 || result[0].Verified != verified {
					t.Fatalf("result = %+v, want verified=%v", result, verified)
				}
			}
			if got := detector.verifyCalls.Load(); got != 1 {
				t.Fatalf("remote verification calls = %d, want 1", got)
			}
			if got := eng.AggregateStats().VerifiedPassesSaved; got != workers-1 {
				t.Fatalf("verified passes saved = %d, want %d", got, workers-1)
			}
		})
	}
}

func TestVerificationCacheKeyIncludesRawV2(t *testing.T) {
	detector := &cacheVerifierDetector{}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential pair-a")},
		{Data: []byte("credential pair-b")},
		{Data: []byte("credential pair-a")},
	}}

	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 2 {
		t.Fatalf("remote verification calls = %d, want 2", got)
	}
}

func TestVerificationCacheReusesOutputStableVerifiedVerdict(t *testing.T) {
	detector := &cacheVerifierDetector{verified: true}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, sink)
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential repeated")},
		{Data: []byte("credential repeated")},
	}}

	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 1 {
		t.Fatalf("remote verification calls = %d, want 1", got)
	}
	for i, finding := range sink.Findings() {
		if !finding.Result.Verified || finding.Result.VerificationErr != nil {
			t.Fatalf("finding %d verdict = %+v, want cached verified", i, finding.Result)
		}
	}
}

func TestVerificationCacheDoesNotCacheIndeterminate(t *testing.T) {
	detector := &cacheVerifierDetector{indeterminate: true}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential repeated")},
		{Data: []byte("credential repeated")},
	}}

	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 2 {
		t.Fatalf("remote verification calls = %d, want 2", got)
	}
}

func TestVerificationCacheDoesNotCacheVerificationMetadataChanges(t *testing.T) {
	detector := &cacheVerifierDetector{verifyMetadata: true}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential repeated")},
		{Data: []byte("credential repeated")},
	}}

	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 2 {
		t.Fatalf("remote verification calls = %d, want 2", got)
	}
}

func TestVerificationCacheDoesNotCollapseConflictingDuplicateVerdicts(t *testing.T) {
	detector := &conflictingDuplicateVerifierDetector{}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})

	for run := 1; run <= 2; run++ {
		results, err := eng.fromData(context.Background(), detector, 0, []byte("credential repeated"))
		if err != nil {
			t.Fatalf("call %d: %v", run, err)
		}
		if len(results) != 2 || !results[0].Verified || results[1].Verified {
			t.Fatalf("call %d results = %+v, want [verified, unverified]", run, results)
		}
	}
	if got := detector.verifyCalls.Load(); got != 2 {
		t.Fatalf("remote verification calls = %d, want 2", got)
	}
}

func TestVerificationCacheDoesNotOverrideDryVerdict(t *testing.T) {
	detector := &cacheVerifierDetector{dryVerified: true}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("credential repeated")},
		{Data: []byte("credential repeated")},
	}}

	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 2 {
		t.Fatalf("remote verification calls = %d, want 2", got)
	}
}

func TestVerificationCacheIsScopedToOneRun(t *testing.T) {
	detector := &cacheVerifierDetector{}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
	newSource := func() *stubSource {
		return &stubSource{chunks: []*sources.Chunk{
			{Data: []byte("credential repeated")},
			{Data: []byte("credential repeated")},
		}}
	}

	if _, err := eng.RunWithStats(context.Background(), newSource()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, err := eng.RunWithStats(context.Background(), newSource()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := detector.verifyCalls.Load(); got != 2 {
		t.Fatalf("remote verification calls across two runs = %d, want 2", got)
	}
}

func TestVerificationCacheEvictsOldestEntry(t *testing.T) {
	cache := newVerificationCache(2)
	keyA := verificationCacheKey{1}
	keyB := verificationCacheKey{2}
	keyC := verificationCacheKey{3}
	cache.set(keyA)
	cache.set(keyB)
	if got := cache.setAll([]verificationCacheEntry{{key: keyC}}); got != 1 {
		t.Fatalf("evictions = %d, want 1", got)
	}

	if cache.has(keyA) {
		t.Fatal("oldest cache entry was not evicted")
	}
	if !cache.has(keyB) {
		t.Fatal("key B was unexpectedly evicted")
	}
	if !cache.has(keyC) {
		t.Fatal("key C was unexpectedly evicted")
	}
}

func TestVerificationCacheKeyIsLengthDelimitedAndDetectorScoped(t *testing.T) {
	inputDigest := sha256.Sum256([]byte("same input"))
	first, ok := verificationKey(0, detectors.AWS, detectors.Result{
		Raw:   []byte("a"),
		RawV2: []byte("bc"),
	}, inputDigest)
	if !ok {
		t.Fatal("first key was not cacheable")
	}
	second, ok := verificationKey(0, detectors.AWS, detectors.Result{
		Raw:   []byte("ab"),
		RawV2: []byte("c"),
	}, inputDigest)
	if !ok {
		t.Fatal("second key was not cacheable")
	}
	otherDetector, ok := verificationKey(0, detectors.GitHub, detectors.Result{
		Raw:   []byte("a"),
		RawV2: []byte("bc"),
	}, inputDigest)
	if !ok {
		t.Fatal("other detector key was not cacheable")
	}
	if first == second {
		t.Fatal("Raw and RawV2 boundaries collided")
	}
	if first == otherDetector {
		t.Fatal("different detector types collided")
	}
	otherInstance, ok := verificationKey(1, detectors.AWS, detectors.Result{
		Raw:   []byte("a"),
		RawV2: []byte("bc"),
	}, inputDigest)
	if !ok {
		t.Fatal("other detector instance key was not cacheable")
	}
	if first == otherInstance {
		t.Fatal("different detector instances collided")
	}
}

func TestVerificationCacheKeyIncludesDetectorInput(t *testing.T) {
	result := detectors.Result{Raw: []byte("same-credential")}
	first, ok := verificationKey(0, detectors.AWS, result, sha256.Sum256([]byte("host-a credential")))
	if !ok {
		t.Fatal("first key was not cacheable")
	}
	second, ok := verificationKey(0, detectors.AWS, result, sha256.Sum256([]byte("host-b credential")))
	if !ok {
		t.Fatal("second key was not cacheable")
	}
	if first == second {
		t.Fatal("different detector inputs collided")
	}
}

func BenchmarkVerificationCache(b *testing.B) {
	b.Run("repeated_negative", func(b *testing.B) {
		for _, enabled := range []bool{false, true} {
			name := "disabled"
			if enabled {
				name = "enabled"
			}
			b.Run(name, func(b *testing.B) {
				detector := &cacheVerifierDetector{verifyDelay: 100 * time.Microsecond}
				eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
				data := []byte("credential repeated")
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var err error
					if enabled {
						_, err = eng.fromData(context.Background(), detector, 0, data)
					} else {
						_, err = detector.FromData(context.Background(), true, data)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(detector.verifyCalls.Load())/float64(b.N), "verified_calls/op")
			})
		}
	})

	b.Run("unique_negative", func(b *testing.B) {
		for _, enabled := range []bool{false, true} {
			name := "disabled"
			if enabled {
				name = "enabled"
			}
			b.Run(name, func(b *testing.B) {
				detector := &cacheVerifierDetector{rawFromData: true}
				eng := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, &engineRecordingSink{})
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					data := strconv.AppendInt([]byte("credential-"), int64(i), 10)
					var err error
					if enabled {
						_, err = eng.fromData(context.Background(), detector, 0, data)
					} else {
						_, err = detector.FromData(context.Background(), true, data)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(detector.verifyCalls.Load())/float64(b.N), "verified_calls/op")
			})
		}
	})
}
