// Package dlp is pleno-dlp's stable, embeddable Go API.
//
// It is the only package whose exported surface carries a compatibility
// promise (see docs/library.md): every other package under pkg/ is an
// implementation detail that may change between minor releases. The C ABI
// in cmd/libpleno-dlp and the Python and Node.js bindings are thin
// wrappers over this package, so all three languages share one contract.
//
// The API covers four operations:
//
//   - ScanBytes / ScanPaths: detect secrets in memory or on disk.
//   - Verify: confirm one candidate secret with its provider.
//   - Revoke: invalidate one secret through its provider's API.
//   - Detectors: enumerate the registered detectors and their capabilities.
//
// Scans are offline by default. Network side effects require explicit
// opt-in: ScanOptions.Verify for verification during a scan, and
// RevokeOptions.Confirm for revocation, mirroring the CLI's safety gates.
// Findings never carry the plaintext secret unless ScanOptions.IncludeRaw
// is set.
package dlp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all" // register the built-in detector set
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/filesystem"
)

// APIVersion is the version of this package's contract. It increments its
// major component only on a breaking change to an exported identifier or
// to the JSON shape of Finding, VerifyResult, RevokeResult, or Detector.
const APIVersion = "1.0.0"

// Errors returned by this package. Callers should match them with errors.Is.
var (
	// ErrUnknownDetector means the detector name matches no registered detector.
	ErrUnknownDetector = errors.New("dlp: unknown detector")
	// ErrNotSupported means the detector does not implement the requested operation.
	ErrNotSupported = errors.New("dlp: operation not supported by detector")
	// ErrNotConfirmed means Revoke was called without Confirm or DryRun.
	ErrNotConfirmed = errors.New("dlp: revoke requires Confirm or DryRun")
)

// ScanOptions configures ScanBytes and ScanPaths. The zero value is an
// offline scan with the full detector set and engine-default concurrency.
type ScanOptions struct {
	// Verify enables provider verification for detectors that support it.
	// It sends candidate secrets to their providers; leave it false for an
	// offline scan.
	Verify bool `json:"verify,omitempty"`
	// IncludeRaw copies the plaintext secret into Finding.Raw and
	// Finding.RawV2. Leave it false unless the caller must act on the value.
	IncludeRaw bool `json:"include_raw,omitempty"`
	// Detectors restricts the scan to these detector names (case
	// sensitive, as reported by Detectors). Empty means all detectors.
	Detectors []string `json:"detectors,omitempty"`
	// Concurrency bounds engine workers. Zero or negative selects the
	// engine default.
	Concurrency int `json:"concurrency,omitempty"`
	// MaxFileSize skips files larger than this many bytes in ScanPaths.
	// Zero selects the filesystem source default.
	MaxFileSize int64 `json:"max_file_size,omitempty"`
}

// Finding is one detected secret. Its JSON shape is part of the stable
// contract.
type Finding struct {
	Detector    string            `json:"detector"`
	Verified    bool              `json:"verified"`
	Verdict     string            `json:"verdict"`
	Assurance   string            `json:"assurance,omitempty"`
	Severity    string            `json:"severity"`
	Redacted    string            `json:"redacted"`
	Raw         string            `json:"raw,omitempty"`
	RawV2       string            `json:"raw_v2,omitempty"`
	Path        string            `json:"path,omitempty"`
	Line        int               `json:"line,omitempty"`
	VerifyError string            `json:"verify_error,omitempty"`
	ExtraData   map[string]string `json:"extra_data,omitempty"`
}

// VerifyResult is the outcome of Verify.
type VerifyResult struct {
	Detector string `json:"detector"`
	// Verified reports whether the provider confirmed the secret is live.
	Verified bool `json:"verified"`
	// Error carries a verification failure that left the verdict
	// indeterminate (network error, unexpected provider response).
	Error string `json:"error,omitempty"`
}

// RevokeOptions gates Revoke. Exactly one of Confirm or DryRun must be set.
type RevokeOptions struct {
	// Confirm authorises the irreversible provider call.
	Confirm bool `json:"confirm,omitempty"`
	// DryRun validates the detector name and capability without contacting
	// the provider.
	DryRun bool `json:"dry_run,omitempty"`
}

// RevokeResult is the outcome of Revoke.
type RevokeResult struct {
	Detector   string    `json:"detector"`
	Revoked    bool      `json:"revoked"`
	DryRun     bool      `json:"dry_run,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitzero"`
	ProviderID string    `json:"provider_id,omitempty"`
	Note       string    `json:"note,omitempty"`
}

// Detector describes one registered detector.
type Detector struct {
	Name      string   `json:"name"`
	Keywords  []string `json:"keywords"`
	CanVerify bool     `json:"can_verify"`
	CanRevoke bool     `json:"can_revoke"`
}

var (
	indexOnce sync.Once
	byName    map[string]detectors.Detector
)

func index() map[string]detectors.Detector {
	indexOnce.Do(func() {
		all := detectors.All()
		byName = make(map[string]detectors.Detector, len(all))
		for _, d := range all {
			byName[d.Type().String()] = d
		}
	})
	return byName
}

func lookup(name string) (detectors.Detector, error) {
	d, ok := index()[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownDetector, name)
	}
	return d, nil
}

// Detectors returns every registered detector sorted by name.
func Detectors() []Detector {
	idx := index()
	out := make([]Detector, 0, len(idx))
	for name, d := range idx {
		_, v := d.(detectors.Verifier)
		_, r := d.(detectors.Revoker)
		out = append(out, Detector{Name: name, Keywords: append([]string{}, d.Keywords()...), CanVerify: v, CanRevoke: r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func selectDetectors(names []string) ([]detectors.Detector, error) {
	if len(names) == 0 {
		return detectors.All(), nil
	}
	out := make([]detectors.Detector, 0, len(names))
	for _, n := range names {
		d, err := lookup(n)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

type collector struct {
	mu         sync.Mutex
	includeRaw bool
	out        []Finding
}

func (c *collector) Emit(f engine.Finding) {
	r := f.Result
	fd := Finding{
		Detector:  r.DetectorType.String(),
		Verified:  r.Verified,
		Verdict:   r.Verdict().String(),
		Severity:  r.Severity.String(),
		Redacted:  r.SafeRedacted(),
		ExtraData: r.ExtraData,
	}
	if r.VerificationAssurance != 0 {
		fd.Assurance = r.VerificationAssurance.String()
	}
	if r.VerificationErr != nil {
		fd.VerifyError = r.VerificationErr.Error()
	}
	if c.includeRaw {
		fd.Raw, fd.RawV2 = string(r.Raw), string(r.RawV2)
	}
	if f.Chunk != nil && f.Chunk.SourceMetadata.Filesystem != nil {
		fd.Path = f.Chunk.SourceMetadata.Filesystem.Path
		fd.Line = f.Chunk.SourceMetadata.Filesystem.Line
	}
	c.mu.Lock()
	c.out = append(c.out, fd)
	c.mu.Unlock()
}

func (c *collector) Close() error { return nil }

func run(ctx context.Context, src sources.Source, opts ScanOptions) ([]Finding, error) {
	dets, err := selectDetectors(opts.Detectors)
	if err != nil {
		return nil, err
	}
	c := &collector{includeRaw: opts.IncludeRaw}
	eng := engine.NewWithDetectors(dets, engine.Options{Concurrency: opts.Concurrency, NoVerify: !opts.Verify}, c)
	_, err = eng.RunWithStats(ctx, src)
	return c.out, err
}

type bytesSource struct{ chunk *sources.Chunk }

func (s *bytesSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}

func (s *bytesSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	select {
	case ch <- s.chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *bytesSource) Type() sources.SourceType { return sources.SourceUnknown }

// ScanBytes scans an in-memory buffer. The returned findings carry no Path.
func ScanBytes(ctx context.Context, data []byte, opts ScanOptions) ([]Finding, error) {
	return run(ctx, &bytesSource{chunk: &sources.Chunk{
		SourceType: sources.SourceUnknown,
		SourceName: "dlp",
		Data:       data,
	}}, opts)
}

// ScanPaths recursively scans files and directories with the same default
// excludes as `pleno-dlp scan filesystem`.
func ScanPaths(ctx context.Context, paths []string, opts ScanOptions) ([]Finding, error) {
	cfg, err := json.Marshal(filesystem.Config{Paths: paths, MaxSizeBytes: opts.MaxFileSize})
	if err != nil {
		return nil, err
	}
	src := &filesystem.Source{}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 4
	}
	if err := src.Init(ctx, "dlp", 0, 0, opts.Verify, cfg, conc); err != nil {
		return nil, err
	}
	return run(ctx, src, opts)
}

// Verify asks the named detector's provider whether secret is live. It
// always performs a network call; ErrNotSupported is returned for
// detectors without a Verifier.
func Verify(ctx context.Context, detector, secret string) (VerifyResult, error) {
	d, err := lookup(detector)
	if err != nil {
		return VerifyResult{}, err
	}
	v, ok := d.(detectors.Verifier)
	if !ok {
		return VerifyResult{}, fmt.Errorf("%w: %s cannot verify", ErrNotSupported, detector)
	}
	res := VerifyResult{Detector: detector}
	live, verr := v.Verify(ctx, secret)
	res.Verified = live
	if verr != nil {
		res.Error = verr.Error()
	}
	return res, nil
}

// Revoke invalidates secret through the named detector's provider. Revoke
// is irreversible; it requires RevokeOptions.Confirm, and DryRun only
// checks that the detector supports revocation.
func Revoke(ctx context.Context, detector, secret string, opts RevokeOptions) (RevokeResult, error) {
	if opts.Confirm == opts.DryRun {
		return RevokeResult{}, ErrNotConfirmed
	}
	d, err := lookup(detector)
	if err != nil {
		return RevokeResult{}, err
	}
	r, ok := d.(detectors.Revoker)
	if !ok {
		return RevokeResult{}, fmt.Errorf("%w: %s cannot revoke", ErrNotSupported, detector)
	}
	if opts.DryRun {
		return RevokeResult{Detector: detector, DryRun: true}, nil
	}
	pr, err := r.Revoke(ctx, secret)
	if err != nil {
		return RevokeResult{}, err
	}
	out := RevokeResult{Detector: detector, Revoked: pr.Revoked, RevokedAt: pr.RevokedAt, ProviderID: pr.ProviderID}
	if pr.Err != nil {
		out.Note = pr.Err.Error()
	}
	return out, nil
}
