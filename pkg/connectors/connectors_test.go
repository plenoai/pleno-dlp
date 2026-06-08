package connectors

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// regCounter makes every test-registered name unique per invocation. The
// connectors registry is a process-global map with no deregister API, so
// fixed names collide (and Register panics) under `go test -count=N>1`.
// Deriving names from an atomic counter keeps the suite idempotent.
var regCounter atomic.Int64

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, regCounter.Add(1))
}

// TestRegisterGetRoundTrip asserts a registered connector is retrievable by
// name with its fields intact, and that an unknown name yields (zero, false).
func TestRegisterGetRoundTrip(t *testing.T) {
	name := uniqueName("test-roundtrip")
	want := Connector{SourceType: sources.SourceFilesystem}
	Register(name, want)

	got, ok := Get(name)
	if !ok {
		t.Fatalf("Get(%q) ok = false, want true", name)
	}
	if got.SourceType != want.SourceType {
		t.Fatalf("Get(%q).SourceType = %v, want %v", name, got.SourceType, want.SourceType)
	}

	if _, ok := Get(uniqueName("test-roundtrip-unknown")); ok {
		t.Fatal("Get(unknown) ok = true, want false")
	}
}

// TestRegisterDuplicatePanics asserts Register panics loudly on a duplicate
// name so an accidental double-init at process start fails immediately.
func TestRegisterDuplicatePanics(t *testing.T) {
	name := uniqueName("test-duplicate")
	Register(name, Connector{SourceType: sources.SourceFilesystem})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Register(duplicate) did not panic, want panic")
		}
	}()
	Register(name, Connector{SourceType: sources.SourceFilesystem})
}

// TestAsSourceUnknownName asserts AsSource errors for a name no connector
// registered under, without returning a non-nil source.
func TestAsSourceUnknownName(t *testing.T) {
	src, err := AsSource(uniqueName("test-assource-unknown"), Config{})
	if err == nil {
		t.Fatal("AsSource(unknown) err = nil, want error")
	}
	if src != nil {
		t.Fatalf("AsSource(unknown) src = %v, want nil", src)
	}
}

// TestAsSourceNilScan asserts AsSource refuses a connector that registered no
// Scan func (verify/revoke-only connectors cannot drive a scan).
func TestAsSourceNilScan(t *testing.T) {
	name := uniqueName("test-assource-nilscan")
	Register(name, Connector{SourceType: sources.SourceFilesystem}) // Scan == nil

	src, err := AsSource(name, Config{})
	if err == nil {
		t.Fatal("AsSource(nil-scan) err = nil, want error")
	}
	if src != nil {
		t.Fatalf("AsSource(nil-scan) src = %v, want nil", src)
	}
}

// TestAsSourceChunksHappyPath drives the full Emit -> Chunk bridge: a fake
// connector emits N items, and the adapter must stamp every framework-owned
// field (SourceID / SourceType / SourceName / Verify) and forward the
// connector-supplied Data + Metadata. Run under -race to catch the send loop
// racing with the consumer.
func TestAsSourceChunksHappyPath(t *testing.T) {
	name := uniqueName("test-assource-happy")
	const n = 5

	scan := func(ctx context.Context, cfg Config, emit Emit) error {
		for i := 0; i < n; i++ {
			meta := sources.Metadata{Filesystem: &sources.FilesystemMeta{
				Path: fmt.Sprintf("/item/%d", i),
				Line: i,
			}}
			if err := emit([]byte(fmt.Sprintf("data-%d", i)), meta); err != nil {
				return err
			}
		}
		return nil
	}
	Register(name, Connector{SourceType: sources.SourceFilesystem, Scan: scan})

	src, err := AsSource(name, Config{"k": "v"})
	if err != nil {
		t.Fatalf("AsSource: %v", err)
	}
	const (
		sourceID   = int64(42)
		sourceName = "happy-source"
	)
	if err := src.Init(context.Background(), sourceName, 1, sourceID, true, nil, 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if src.Type() != sources.SourceFilesystem {
		t.Fatalf("Type() = %v, want %v", src.Type(), sources.SourceFilesystem)
	}

	ch := make(chan *sources.Chunk)
	errCh := make(chan error, 1)
	go func() { errCh <- src.Chunks(context.Background(), ch) }()

	var got int
	seenPaths := map[string]bool{}
	for got < n {
		c := <-ch
		got++
		if c.SourceID != sourceID {
			t.Errorf("chunk SourceID = %d, want %d", c.SourceID, sourceID)
		}
		if c.SourceType != sources.SourceFilesystem {
			t.Errorf("chunk SourceType = %v, want %v", c.SourceType, sources.SourceFilesystem)
		}
		if c.SourceName != sourceName {
			t.Errorf("chunk SourceName = %q, want %q", c.SourceName, sourceName)
		}
		if !c.Verify {
			t.Errorf("chunk Verify = false, want true (Init verify=true)")
		}
		if c.SourceMetadata.Filesystem == nil {
			t.Fatalf("chunk Metadata.Filesystem = nil, want stamped meta")
		}
		seenPaths[c.SourceMetadata.Filesystem.Path] = true
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Chunks returned error: %v", err)
	}
	if got != n {
		t.Fatalf("received %d chunks, want %d", got, n)
	}
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("/item/%d", i)
		if !seenPaths[p] {
			t.Errorf("missing chunk for path %q", p)
		}
	}
}

// TestChunksCancellationPropagates asserts the Emit -> ch send honours
// ctx.Done(): when the consumer never reads and the context is cancelled, the
// emit returns ctx.Err() and Chunks unwinds instead of blocking forever.
func TestChunksCancellationPropagates(t *testing.T) {
	name := uniqueName("test-assource-cancel")

	emitErr := make(chan error, 1)
	scan := func(ctx context.Context, cfg Config, emit Emit) error {
		// First emit blocks on an unread channel until the ctx is cancelled.
		err := emit([]byte("blocked"), sources.Metadata{})
		emitErr <- err
		return err
	}
	Register(name, Connector{SourceType: sources.SourceFilesystem, Scan: scan})

	src, err := AsSource(name, Config{})
	if err != nil {
		t.Fatalf("AsSource: %v", err)
	}
	if err := src.Init(context.Background(), "cancel-source", 1, 7, false, nil, 1); err != nil {
		t.Fatalf("Init: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *sources.Chunk) // never read
	done := make(chan error, 1)
	go func() { done <- src.Chunks(ctx, ch) }()

	cancel()

	if got := <-emitErr; got == nil {
		t.Fatal("emit on cancelled ctx returned nil, want ctx error")
	}
	if err := <-done; err == nil {
		t.Fatal("Chunks returned nil after cancel, want ctx error")
	}
}

func TestAsSourceResourceFingerprint(t *testing.T) {
	name := uniqueName("test-assource-fingerprint")
	Register(name, Connector{
		SourceType: sources.SourceFilesystem,
		Scan: func(context.Context, Config, Emit) error {
			return nil
		},
		Fingerprint: func(ctx context.Context, cfg Config) (string, error) {
			if got := cfg["k"]; got != "v" {
				t.Fatalf("Fingerprint cfg[k] = %q, want v", got)
			}
			return "fp-123", nil
		},
	})

	src, err := AsSource(name, Config{"k": "v"})
	if err != nil {
		t.Fatalf("AsSource: %v", err)
	}
	fp, ok := src.(sources.ResourceFingerprinter)
	if !ok {
		t.Fatal("source adapter must expose ResourceFingerprinter")
	}
	got, err := fp.ResourceFingerprint(context.Background())
	if err != nil {
		t.Fatalf("ResourceFingerprint: %v", err)
	}
	if got != "fp-123" {
		t.Fatalf("ResourceFingerprint = %q, want fp-123", got)
	}
}

func TestAsSourceIncrementalState(t *testing.T) {
	name := uniqueName("test-assource-incremental-state")
	Register(name, Connector{
		SourceType: sources.SourceFilesystem,
		Scan: func(_ context.Context, cfg Config, _ Emit) error {
			if got := cfg[configKeyIncrementalPreviousState]; got != `{"repos":{}}` {
				t.Fatalf("previous incremental state = %q, want JSON payload", got)
			}
			cfg[configKeyIncrementalNextState] = `{"repos":{"acme/widget":{}}}`
			return nil
		},
	})

	src, err := AsSource(name, Config{})
	if err != nil {
		t.Fatalf("AsSource: %v", err)
	}
	iss, ok := src.(sources.IncrementalStateSource)
	if !ok {
		t.Fatal("source adapter must expose IncrementalStateSource")
	}
	if err := iss.SetIncrementalState([]byte(`{"repos":{}}`)); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	ch := make(chan *sources.Chunk)
	go func() {
		if err := src.Chunks(context.Background(), ch); err != nil {
			t.Errorf("Chunks: %v", err)
		}
		close(ch)
	}()
	for range ch {
	}
	if got := string(iss.IncrementalState()); got != `{"repos":{"acme/widget":{}}}` {
		t.Fatalf("IncrementalState = %q", got)
	}
}
