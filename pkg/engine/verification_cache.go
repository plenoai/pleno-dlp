package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const defaultVerificationCacheCapacity = 100_000

type verificationCacheKey [sha256.Size]byte

type verificationCacheEntry struct {
	key      verificationCacheKey
	verified bool
}

type verificationFlightResult struct {
	results   []detectors.Result
	usedCache bool
}

// verificationCache retains only hashes and verdict bits for output-stable
// candidates. Raw credentials, result metadata, and transient errors are never
// kept.
type verificationCache struct {
	mu       sync.RWMutex
	capacity int
	values   map[verificationCacheKey]bool
	order    []verificationCacheKey
	next     int
}

func newVerificationCache(capacity int) *verificationCache {
	if capacity < 0 {
		capacity = 0
	}
	return &verificationCache{
		capacity: capacity,
		values:   make(map[verificationCacheKey]bool),
	}
}

func (c *verificationCache) has(key verificationCacheKey) bool {
	_, ok := c.get(key)
	return ok
}

func (c *verificationCache) get(key verificationCacheKey) (bool, bool) {
	if c == nil || c.capacity == 0 {
		return false, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	verified, ok := c.values[key]
	return verified, ok
}

func (c *verificationCache) set(key verificationCacheKey) {
	c.setAll([]verificationCacheEntry{{key: key}})
}

func (c *verificationCache) setAll(entries []verificationCacheEntry) int64 {
	if c == nil || c.capacity == 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var evictions int64
	for _, entry := range entries {
		if _, ok := c.values[entry.key]; ok {
			c.values[entry.key] = entry.verified
			continue
		}
		if len(c.order) < c.capacity {
			c.order = append(c.order, entry.key)
		} else {
			delete(c.values, c.order[c.next])
			c.order[c.next] = entry.key
			c.next = (c.next + 1) % c.capacity
			evictions++
		}
		c.values[entry.key] = entry.verified
	}
	return evictions
}

func (c *verificationCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.values)
	c.order = c.order[:0]
	c.next = 0
}

func verificationKey(detectorIndex int, detectorType detectors.DetectorType, result detectors.Result, inputDigest [sha256.Size]byte) (verificationCacheKey, bool) {
	if len(result.Raw) == 0 && len(result.RawV2) == 0 {
		return verificationCacheKey{}, false
	}
	h := sha256.New()
	var header [28]byte
	binary.BigEndian.PutUint32(header[0:4], uint32(detectorType))
	binary.BigEndian.PutUint64(header[4:12], uint64(detectorIndex))
	binary.BigEndian.PutUint64(header[12:20], uint64(len(result.Raw)))
	binary.BigEndian.PutUint64(header[20:28], uint64(len(result.RawV2)))
	_, _ = h.Write(header[:])
	_, _ = h.Write(result.Raw)
	_, _ = h.Write(result.RawV2)
	_, _ = h.Write(inputDigest[:])
	var key verificationCacheKey
	_ = h.Sum(key[:0])
	return key, true
}

func verificationFlightKey(keys []verificationCacheKey) string {
	if len(keys) == 1 {
		return string(keys[0][:])
	}
	ordered := append([]verificationCacheKey(nil), keys...)
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i][:], ordered[j][:]) < 0
	})
	h := sha256.New()
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(ordered)))
	_, _ = h.Write(count[:])
	for _, key := range ordered {
		_, _ = h.Write(key[:])
	}
	return string(h.Sum(nil))
}

// fromData mirrors TruffleHog's cache-aware detector flow: detect without
// remote verification first, reuse the cache only when every candidate is a
// hit, and otherwise preserve the detector's original verified call. Detector
// implementations must return the same candidate set for verify=false and
// verify=true; verification may only enrich each candidate's verdict metadata.
func (e *Engine) fromData(ctx context.Context, detector detectors.Detector, detectorIndex int, data []byte) ([]detectors.Result, error) {
	verify := !e.opts.NoVerify
	if minimum := e.opts.MinimumVerificationAssurance; verify && minimum != detectors.AssuranceUnknown {
		verify = e.verificationAssurance[detectorIndex] >= minimum
	}
	if !verify || !e.isVerifier[detectorIndex] {
		return detector.FromData(ctx, verify, data)
	}
	if !e.verificationCacheable[detectorIndex] {
		e.stats.verificationCacheBypasses.Add(1)
		return e.callVerifiedDetector(ctx, detector, data)
	}

	var inputDigest [sha256.Size]byte
	if e.verificationUsesData[detectorIndex] {
		inputDigest = sha256.Sum256(data)
	}
	unverified, err := detector.FromData(ctx, false, data)
	if err != nil {
		return nil, err
	}
	keys, ok := candidateVerificationKeys(detectorIndex, detector.Type(), inputDigest, unverified)
	if !ok {
		return e.callVerifiedDetector(ctx, detector, data)
	}
	if e.applyCachedVerification(keys, unverified, true) {
		if len(unverified) > 0 {
			e.stats.verifiedPassesSaved.Add(1)
		}
		return unverified, nil
	}

	executed := false
	value, flightErr, _ := e.verificationFlights.Do(verificationFlightKey(keys), func() (any, error) {
		executed = true
		if e.applyCachedVerification(keys, unverified, false) {
			return verificationFlightResult{usedCache: true}, nil
		}
		verified, verifyErr := e.callVerifiedDetector(ctx, detector, data)
		if verifyErr == nil {
			cacheEntries := cacheableVerificationEntries(
				detectorIndex,
				detector.Type(),
				inputDigest,
				unverified,
				verified,
			)
			e.stats.verificationCacheEvictions.Add(e.verificationCache.setAll(cacheEntries))
		}
		return verificationFlightResult{results: verified}, verifyErr
	})
	outcome := value.(verificationFlightResult)
	if executed && !outcome.usedCache {
		return outcome.results, flightErr
	}
	if e.applyCachedVerification(keys, unverified, true) {
		e.stats.verifiedPassesSaved.Add(1)
		return unverified, nil
	}
	// An indeterminate, erroring, or output-changing result is never
	// cached. Waiters preserve their own detector call and result in those
	// cases instead of inheriting the in-flight caller's context or metadata.
	return e.callVerifiedDetector(ctx, detector, data)
}

func candidateVerificationKeys(detectorIndex int, detectorType detectors.DetectorType, inputDigest [sha256.Size]byte, results []detectors.Result) ([]verificationCacheKey, bool) {
	keys := make([]verificationCacheKey, 0, len(results))
	for i := range results {
		key, ok := verificationKey(detectorIndex, detectorType, results[i], inputDigest)
		if !ok || results[i].Verified || results[i].VerificationErr != nil {
			return nil, false
		}
		keys = append(keys, key)
	}
	return keys, true
}

func (e *Engine) applyCachedVerification(keys []verificationCacheKey, results []detectors.Result, recordStats bool) bool {
	var hits int64
	verdicts := make([]bool, 0, len(keys))
	for _, key := range keys {
		verified, ok := e.verificationCache.get(key)
		if !ok {
			if recordStats {
				e.stats.verificationCacheMisses.Add(1)
				e.stats.verificationCacheHitsWasted.Add(hits)
			}
			return false
		}
		verdicts = append(verdicts, verified)
		hits++
	}
	for i, verified := range verdicts {
		results[i].Verified = verified
	}
	if recordStats {
		e.stats.verificationCacheHits.Add(hits)
	}
	return true
}

func (e *Engine) callVerifiedDetector(ctx context.Context, detector detectors.Detector, data []byte) ([]detectors.Result, error) {
	verifyStart := time.Now()
	verified, err := detector.FromData(ctx, true, data)
	e.stats.verifiedDetectorCalls.Add(1)
	e.stats.verifiedDetectorCallNanos.Add(time.Since(verifyStart).Nanoseconds())
	return verified, err
}

func cacheableVerificationEntries(detectorIndex int, detectorType detectors.DetectorType, inputDigest [sha256.Size]byte, unverified, verified []detectors.Result) []verificationCacheEntry {
	if len(unverified) == 0 || len(unverified) != len(verified) {
		return nil
	}
	used := make([]bool, len(verified))
	entries := make([]verificationCacheEntry, 0, len(unverified))
	verdicts := make(map[verificationCacheKey]bool, len(unverified))
	for _, before := range unverified {
		key, ok := verificationKey(detectorIndex, detectorType, before, inputDigest)
		if !ok || before.Verified || before.VerificationErr != nil {
			return nil
		}
		match := -1
		for i, after := range verified {
			if used[i] || after.VerificationErr != nil {
				continue
			}
			afterKey, ok := verificationKey(detectorIndex, detectorType, after, inputDigest)
			if ok && key == afterKey && equalExceptVerification(before, after) {
				match = i
				break
			}
		}
		if match < 0 {
			return nil
		}
		used[match] = true
		verdict := verified[match].Verified
		if cachedVerdict, exists := verdicts[key]; exists {
			if cachedVerdict != verdict {
				return nil
			}
			continue
		}
		verdicts[key] = verdict
		entries = append(entries, verificationCacheEntry{
			key:      key,
			verified: verdict,
		})
	}
	return entries
}

func equalExceptVerification(a, b detectors.Result) bool {
	a.Verified = false
	a.VerificationErr = nil
	b.Verified = false
	b.VerificationErr = nil
	return reflect.DeepEqual(a, b)
}
