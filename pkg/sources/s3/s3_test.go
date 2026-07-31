package s3

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	archivepkg "github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type fakeS3Client struct {
	objects []types.Object
	get     func(context.Context, string) (io.ReadCloser, error)
	listErr error

	mu        sync.Mutex
	getCalls  []string
	listCalls int
}

func (f *fakeS3Client) ListObjectsV2(context.Context, *awss3.ListObjectsV2Input, ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	f.mu.Lock()
	f.listCalls++
	f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &awss3.ListObjectsV2Output{Contents: f.objects}, nil
}

func (f *fakeS3Client) GetObject(ctx context.Context, in *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	key := aws.ToString(in.Key)
	f.mu.Lock()
	f.getCalls = append(f.getCalls, key)
	f.mu.Unlock()
	body, err := f.get(ctx, key)
	if err != nil {
		return nil, err
	}
	return &awss3.GetObjectOutput{
		Body:      body,
		ETag:      aws.String(`"downloaded"`),
		VersionId: aws.String("v1"),
	}, nil
}

func (f *fakeS3Client) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.getCalls...)
}

func (f *fakeS3Client) lists() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

func object(key string, size int64) types.Object {
	return types.Object{
		Key:          aws.String(key),
		ETag:         aws.String(`"` + key + `"`),
		Size:         aws.Int64(size),
		LastModified: aws.Time(time.Unix(1, 0).UTC()),
	}
}

func testSource(client s3API, concurrency int, maxSize int64) *Source {
	return &Source{
		name:         "test",
		sourceID:     1,
		concurrency:  concurrency,
		bucket:       "example-bucket",
		maxSizeBytes: maxSize,
		client:       client,
		progress:     io.Discard,
	}
}

func collect(t *testing.T, s *Source) ([]*sources.Chunk, error) {
	t.Helper()
	ch := make(chan *sources.Chunk, 16)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Chunks(t.Context(), ch)
		close(ch)
	}()
	var chunks []*sources.Chunk
	for chunk := range ch {
		chunks = append(chunks, chunk)
	}
	return chunks, <-errCh
}

func TestType(t *testing.T) {
	s := &Source{}
	if s.Type() != sources.SourceS3 {
		t.Fatalf("got %v, want SourceS3", s.Type())
	}
}

func TestS3ClientSuppressesSkippedChecksumWarningsWithoutDisablingValidation(t *testing.T) {
	s := &Source{awsCfg: aws.Config{
		Region:                     "us-east-1",
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenSupported,
	}}
	client, ok := s.s3Client().(*awss3.Client)
	if !ok {
		t.Fatalf("s3Client() = %T, want *s3.Client", s.s3Client())
	}
	opts := client.Options()
	if !opts.DisableLogOutputChecksumValidationSkipped {
		t.Fatal("skipped checksum validation warnings are enabled")
	}
	if got, want := opts.ResponseChecksumValidation, aws.ResponseChecksumValidationWhenSupported; got != want {
		t.Fatalf("response checksum validation = %v, want %v", got, want)
	}
}

func TestInitMissingBucket(t *testing.T) {
	s := &Source{}
	cfg, _ := json.Marshal(Config{})
	err := s.Init(context.Background(), "test", 0, 0, false, cfg, 1)
	if err == nil {
		t.Fatal("expected error for missing bucket")
	}
}

func TestInitBadGlob(t *testing.T) {
	s := &Source{}
	cfg, _ := json.Marshal(Config{
		Bucket:  "test-bucket",
		Include: []string{"[invalid"},
	})
	err := s.Init(context.Background(), "test", 0, 0, false, cfg, 1)
	if err == nil {
		t.Fatal("expected error for invalid glob")
	}
}

func TestInitBadJSON(t *testing.T) {
	s := &Source{}
	err := s.Init(context.Background(), "test", 0, 0, false, []byte("{broken"), 1)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestInitDefaultsToTruffleHogComparableObjectLimit(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "placeholder")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "placeholder")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	s := &Source{}
	cfg, _ := json.Marshal(Config{Bucket: "example-bucket"})
	if err := s.Init(t.Context(), "test", 0, 0, false, cfg, 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got, want := s.maxSizeBytes, int64(250<<20); got != want {
		t.Fatalf("maxSizeBytes = %d, want %d", got, want)
	}
}

func TestInitRejectsUnsafeObjectLimitAndLongRoleChain(t *testing.T) {
	tests := []Config{
		{Bucket: "example-bucket", MaxSizeBytes: 250<<20 + 1},
		{Bucket: "example-bucket", RoleARNs: []string{"role-a", "role-b", "role-c"}},
		{Bucket: "example-bucket", RoleARNs: []string{"role-a", ""}},
	}
	for _, cfg := range tests {
		raw, _ := json.Marshal(cfg)
		if err := (&Source{}).Init(t.Context(), "test", 0, 0, false, raw, 1); err == nil {
			t.Fatalf("Init(%+v) should fail", cfg)
		}
	}
}

type staticCredentialsProvider string

func (p staticCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: string(p), SecretAccessKey: "placeholder"}, nil
}

func TestApplyAssumeRoleChainCachesEveryHop(t *testing.T) {
	baseProvider := staticCredentialsProvider("base")
	cfg := aws.Config{Credentials: baseProvider}
	var inputs []aws.CredentialsProvider
	var roles []string
	var sessions []string

	got := applyAssumeRoleChain(cfg, []string{"role-a", "role-b"}, "scan-session",
		func(cfg aws.Config, roleARN, sessionName string) aws.CredentialsProvider {
			inputs = append(inputs, cfg.Credentials)
			roles = append(roles, roleARN)
			sessions = append(sessions, sessionName)
			return staticCredentialsProvider(roleARN)
		})

	if len(inputs) != 2 || inputs[0] != baseProvider {
		t.Fatalf("provider inputs = %#v, want base then cached first hop", inputs)
	}
	if _, ok := inputs[1].(*aws.CredentialsCache); !ok {
		t.Fatalf("second role did not receive cached first-hop credentials: %T", inputs[1])
	}
	if _, ok := got.Credentials.(*aws.CredentialsCache); !ok {
		t.Fatalf("final credentials are not auto-refreshing cache: %T", got.Credentials)
	}
	if strings.Join(roles, ",") != "role-a,role-b" || strings.Join(sessions, ",") != "scan-session,scan-session" {
		t.Fatalf("factory calls roles=%v sessions=%v", roles, sessions)
	}
	creds, err := got.Credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if creds.AccessKeyID != "role-b" {
		t.Fatalf("final provider = %q, want second role", creds.AccessKeyID)
	}
}

func TestKeyAllowed(t *testing.T) {
	tests := []struct {
		name    string
		include []string
		exclude []string
		key     string
		want    bool
	}{
		{"no filters", nil, nil, "foo/bar.txt", true},
		{"include match", []string{"*.txt"}, nil, "foo/bar.txt", true},
		{"include no match", []string{"*.go"}, nil, "foo/bar.txt", false},
		{"exclude match", nil, []string{"*.log"}, "foo/bar.log", false},
		{"exclude trumps include", []string{"*"}, []string{"*.log"}, "foo/bar.log", false},
		{"path glob exclude", nil, []string{"secret/*"}, "secret/key.pem", false},
		{"basename exclude", nil, []string{"*.pem"}, "secret/key.pem", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Source{include: tt.include, exclude: tt.exclude}
			if got := s.keyAllowed(tt.key); got != tt.want {
				t.Errorf("keyAllowed(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("hello world")) {
		t.Error("text classified as binary")
	}
	if !isBinary([]byte{0x00, 0x01, 0x02}) {
		t.Error("binary not detected")
	}
}

func TestRegistered(t *testing.T) {
	src := sources.New(sources.SourceS3)
	if src == nil {
		t.Fatal("S3 source not registered")
	}
	if src.Type() != sources.SourceS3 {
		t.Fatalf("got %v, want SourceS3", src.Type())
	}
}

func TestIncrementalStateSkipsUnchangedObject(t *testing.T) {
	s := &Source{}
	previous := []byte(`{"version":1,"objects":{"a.txt":{"etag":"\"abc\"","size":12,"last_modified":"2026-06-09T00:00:00Z"}}}`)
	if err := s.SetIncrementalState(previous); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}

	unchanged := objectIncrementalState{ETag: `"abc"`, Size: 12, LastModified: "2026-06-09T00:00:00Z"}
	if !s.objectUnchanged("a.txt", unchanged) {
		t.Fatal("unchanged object should be skipped")
	}
	changed := objectIncrementalState{ETag: `"def"`, Size: 12, LastModified: "2026-06-09T00:00:00Z"}
	if s.objectUnchanged("a.txt", changed) {
		t.Fatal("changed object must not be skipped")
	}
	if s.objectUnchanged("new.txt", unchanged) {
		t.Fatal("new object must not be skipped")
	}
}

func TestIncrementalStateRoundTrip(t *testing.T) {
	modified := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	state := stateForObject(types.Object{
		Key:          aws.String("a.txt"),
		ETag:         aws.String(`"abc"`),
		Size:         aws.Int64(12),
		LastModified: aws.Time(modified),
	})
	if got, want := state.LastModified, "2026-06-09T00:00:00Z"; got != want {
		t.Fatalf("LastModified = %q, want %q", got, want)
	}

	s := &Source{nextState: &incrementalState{
		Version: 1,
		Objects: map[string]objectIncrementalState{
			"a.txt": state,
		},
	}}
	raw := s.IncrementalState()
	if len(raw) == 0 {
		t.Fatal("IncrementalState must not be empty")
	}

	var decoded incrementalState
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode IncrementalState: %v", err)
	}
	if decoded.Objects["a.txt"] != state {
		t.Fatalf("decoded state = %#v, want %#v", decoded.Objects["a.txt"], state)
	}
}

func TestChunksDownloadsObjectsConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var active atomic.Int32
	var peak atomic.Int32
	client := &fakeS3Client{
		objects: []types.Object{object("a.txt", 1), object("b.txt", 1)},
		get: func(ctx context.Context, _ string) (io.ReadCloser, error) {
			now := active.Add(1)
			defer active.Add(-1)
			for {
				old := peak.Load()
				if now <= old || peak.CompareAndSwap(old, now) {
					break
				}
			}
			started <- struct{}{}
			select {
			case <-release:
				return io.NopCloser(strings.NewReader("plain text")), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	s := testSource(client, 2, defaultMaxObjectSize)
	ch := make(chan *sources.Chunk, 2)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Chunks(t.Context(), ch)
		close(ch)
	}()

	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("two GetObject calls did not overlap")
		}
	}
	close(release)
	for range ch {
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if got := peak.Load(); got < 2 {
		t.Fatalf("peak GetObject concurrency = %d, want at least 2", got)
	}
}

func TestResourceFingerprintOptsOutWithoutListingBucketTwice(t *testing.T) {
	client := &fakeS3Client{
		objects: []types.Object{object("a.txt", 1)},
		get: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("x")), nil
		},
	}
	s := testSource(client, 1, defaultMaxObjectSize)
	fingerprint, err := s.ResourceFingerprint(t.Context())
	if err != nil {
		t.Fatalf("ResourceFingerprint: %v", err)
	}
	if fingerprint != "" {
		t.Fatalf("fingerprint = %q, want opt-out so per-object state owns incrementality", fingerprint)
	}
	if got := client.lists(); got != 0 {
		t.Fatalf("ResourceFingerprint listed bucket %d time(s), want 0", got)
	}
}

func TestScanSummaryIsCountOnly(t *testing.T) {
	var summary scanSummary
	summary.listed.Add(10)
	summary.scanned.Add(2)
	summary.bytes.Add(123)
	summary.unchanged.Add(1)
	summary.empty.Add(1)
	summary.oversize.Add(1)
	summary.archiveOversize.Add(1)
	summary.binary.Add(1)
	summary.filtered.Add(1)
	summary.directory.Add(1)
	summary.failed.Add(1)
	line := summary.String()
	for _, want := range []string{
		"listed=10", "scanned=2", "bytes=123", "unchanged=1",
		"empty=1", "oversize=1", "archive_oversize=1", "binary=1",
		"filtered=1", "directory=1", "failed=1",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("summary %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "example-bucket") || strings.Contains(line, "object.txt") {
		t.Fatalf("summary exposed object coordinates: %q", line)
	}
}

type readErrorBody struct {
	sent bool
}

func (r *readErrorBody) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, "plain"), nil
	}
	return 0, errors.New("injected read failure")
}

func (*readErrorBody) Close() error { return nil }

func TestChunksAggregatesCoverageErrorsAndRetriesFailedObjects(t *testing.T) {
	client := &fakeS3Client{
		objects: []types.Object{
			object("good.txt", 5),
			object("get-fails.txt", 5),
			object("read-fails.txt", 5),
		},
		get: func(_ context.Context, key string) (io.ReadCloser, error) {
			switch key {
			case "get-fails.txt":
				return nil, errors.New("injected get failure")
			case "read-fails.txt":
				return &readErrorBody{}, nil
			default:
				return io.NopCloser(strings.NewReader("plain")), nil
			}
		},
	}
	first := testSource(client, 3, defaultMaxObjectSize)
	chunks, err := collect(t, first)
	if len(chunks) != 1 {
		t.Fatalf("successful chunks = %d, want 1", len(chunks))
	}
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Total != 2 || degraded.Counts[engine.FailureSource] != 2 {
		t.Fatalf("error = %#v, want two structured source failures", err)
	}

	var state incrementalState
	if err := json.Unmarshal(first.IncrementalState(), &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(state.Objects) != 0 {
		t.Fatalf("degraded scan advanced state = %#v, want empty state for complete-report retry", state.Objects)
	}

	retryClient := &fakeS3Client{
		objects: client.objects,
		get: func(_ context.Context, _ string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("plain")), nil
		},
	}
	retry := testSource(retryClient, 2, defaultMaxObjectSize)
	if err := retry.SetIncrementalState(first.IncrementalState()); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	retried, err := collect(t, retry)
	if err != nil {
		t.Fatalf("retry Chunks: %v", err)
	}
	if len(retried) != 3 {
		t.Fatalf("retry chunks = %d, want complete three-object retry", len(retried))
	}
	if got := len(retryClient.calls()); got != 3 {
		t.Fatalf("retry GetObject calls = %d, want complete retry", got)
	}
}

func TestChunksReportsListingFailureAsDegradedCoverage(t *testing.T) {
	client := &fakeS3Client{
		listErr: errors.New("injected list failure"),
		get: func(context.Context, string) (io.ReadCloser, error) {
			t.Fatal("GetObject must not run after listing failure")
			return nil, nil
		},
	}
	_, err := collect(t, testSource(client, 2, defaultMaxObjectSize))
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Total != 1 || degraded.Counts[engine.FailureSource] != 1 {
		t.Fatalf("error = %#v, want one structured source failure", err)
	}
}

func TestCoverageErrorRedactsObjectKeyAndProviderMessage(t *testing.T) {
	const sensitiveKey = "object-name-with-credential-like-material"
	providerErr := errors.New("provider request failed for " + sensitiveKey)
	client := &fakeS3Client{
		objects: []types.Object{object(sensitiveKey, 1)},
		get: func(context.Context, string) (io.ReadCloser, error) {
			return nil, providerErr
		},
	}
	_, err := collect(t, testSource(client, 1, defaultMaxObjectSize))
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || len(degraded.Failures) != 1 {
		t.Fatalf("error = %#v, want one structured failure", err)
	}
	for _, rendered := range []string{
		err.Error(),
		degraded.Failures[0].Source,
		degraded.Failures[0].Err.Error(),
	} {
		if strings.Contains(rendered, sensitiveKey) {
			t.Fatalf("coverage error exposed object key: %q", rendered)
		}
	}
	if !strings.Contains(degraded.Failures[0].Source, "sha256:") {
		t.Fatalf("failure source lacks opaque correlation hash: %q", degraded.Failures[0].Source)
	}
	if !errors.Is(err, providerErr) {
		t.Fatal("redaction wrapper did not preserve the original error cause")
	}
}

type hostileReadBody struct {
	err error
}

func (r *hostileReadBody) Read([]byte) (int, error) { return 0, r.err }
func (*hostileReadBody) Close() error               { return nil }

func TestCoverageErrorRedactsBodyReadMessage(t *testing.T) {
	const sensitiveKey = "credential-like-key-in-read-error"
	readErr := errors.New("body read failed for " + sensitiveKey)
	client := &fakeS3Client{
		objects: []types.Object{object(sensitiveKey, 1)},
		get: func(context.Context, string) (io.ReadCloser, error) {
			return &hostileReadBody{err: readErr}, nil
		},
	}
	_, err := collect(t, testSource(client, 1, defaultMaxObjectSize))
	if strings.Contains(err.Error(), sensitiveKey) {
		t.Fatalf("coverage error exposed body error text: %q", err)
	}
	if !errors.Is(err, readErr) {
		t.Fatal("redaction wrapper did not preserve body read error cause")
	}
}

func TestChunksPassesArchivePayloadAndCheckpointsAfterEmission(t *testing.T) {
	var payload bytes.Buffer
	zw := zip.NewWriter(&payload)
	w, err := zw.Create("inside.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := io.WriteString(w, "plain archive content"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data := payload.Bytes()
	client := &fakeS3Client{
		objects: []types.Object{object("bundle.zip", int64(len(data)))},
		get: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
	}
	source := testSource(client, 1, defaultMaxObjectSize)
	chunks, err := collect(t, source)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(chunks) != 1 || !archivepkg.LooksLikeArchive(chunks[0].Data) {
		t.Fatalf("archive payload was not emitted intact: chunks=%d", len(chunks))
	}
	var state incrementalState
	if err := json.Unmarshal(source.IncrementalState(), &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if _, ok := state.Objects["bundle.zip"]; !ok {
		t.Fatal("successfully emitted archive was not checkpointed for run-level acknowledgement")
	}
}

func TestChunksRejectsOversizedArchiveWithRetryableCoverage(t *testing.T) {
	var payload bytes.Buffer
	zw := zip.NewWriter(&payload)
	w, err := zw.Create("inside.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := io.WriteString(w, "plain archive content"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data := payload.Bytes()
	client := &fakeS3Client{
		objects: []types.Object{object("large-bundle.zip", maxArchiveObjectSize+1)},
		get: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
	}
	var progress bytes.Buffer
	source := testSource(client, 1, defaultMaxObjectSize)
	source.progress = &progress
	chunks, err := collect(t, source)
	if len(chunks) != 0 {
		t.Fatalf("chunks = %d, want none beyond archive memory cap", len(chunks))
	}
	if !errors.Is(err, errArchiveObjectTooLarge) {
		t.Fatalf("error = %v, want archive size coverage error", err)
	}
	var state incrementalState
	if err := json.Unmarshal(source.IncrementalState(), &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(state.Objects) != 0 {
		t.Fatalf("oversized archive advanced state: %#v", state.Objects)
	}
	if line := progress.String(); !strings.Contains(line, "archive_oversize=1") || !strings.Contains(line, "failed=1") {
		t.Fatalf("safe summary missing archive coverage count: %q", line)
	}
}

func TestChunksDoesNotCheckpointArchiveThatGrowsPastConfiguredLimit(t *testing.T) {
	var payload bytes.Buffer
	zw := zip.NewWriter(&payload)
	header := &zip.FileHeader{Name: "inside.txt", Method: zip.Store}
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("x"), 2048)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data := payload.Bytes()
	limit := int64(len(data) - 1)
	client := &fakeS3Client{
		// The listing is stale by one byte; GetObject returns the grown body.
		objects: []types.Object{object("grew.zip", limit)},
		get: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
	}
	source := testSource(client, 1, limit)
	chunks, err := collect(t, source)
	if len(chunks) != 0 {
		t.Fatalf("chunks = %d, want none beyond configured archive limit", len(chunks))
	}
	if !errors.Is(err, errArchiveObjectTooLarge) {
		t.Fatalf("error = %v, want retryable archive size coverage error", err)
	}
	var state incrementalState
	if err := json.Unmarshal(source.IncrementalState(), &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(state.Objects) != 0 {
		t.Fatalf("grown archive advanced state: %#v", state.Objects)
	}
}

func TestChunksStreamsLargeTextInBoundedOverlappingChunks(t *testing.T) {
	data := bytes.Repeat([]byte("x"), objectChunkSize*2+17)
	copy(data[objectChunkSize-8:], []byte("boundary-marker"))
	client := &fakeS3Client{
		objects: []types.Object{object("large.txt", int64(len(data)))},
		get: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
	}
	chunks, err := collect(t, testSource(client, 1, int64(len(data))))
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(chunks) < 3 {
		t.Fatalf("chunks = %d, want streamed output", len(chunks))
	}
	for i, chunk := range chunks {
		if len(chunk.Data) > objectChunkSize {
			t.Fatalf("chunk %d size = %d, exceeds %d", i, len(chunk.Data), objectChunkSize)
		}
	}
	for i := 1; i < len(chunks); i++ {
		left := chunks[i-1].Data
		right := chunks[i].Data
		if !bytes.Equal(left[len(left)-objectChunkOverlap:], right[:objectChunkOverlap]) {
			t.Fatalf("chunks %d/%d do not preserve boundary overlap", i-1, i)
		}
	}
	reconstructed := append([]byte(nil), chunks[0].Data...)
	for _, chunk := range chunks[1:] {
		reconstructed = append(reconstructed, chunk.Data[objectChunkOverlap:]...)
	}
	if !bytes.Equal(reconstructed, data) {
		t.Fatal("streamed chunks did not reconstruct the original object")
	}
}

func TestChunksDoesNotCheckpointObjectThatGrowsPastLimit(t *testing.T) {
	const limit = int64(1024)
	data := bytes.Repeat([]byte("x"), int(limit+1))
	client := &fakeS3Client{
		objects: []types.Object{object("grew.txt", limit)},
		get: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
	}
	s := testSource(client, 1, limit)
	chunks, err := collect(t, s)
	if len(chunks) != 0 {
		t.Fatalf("chunks = %d, want none for object beyond configured limit", len(chunks))
	}
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Total != 1 {
		t.Fatalf("error = %#v, want degraded coverage", err)
	}
	var state incrementalState
	if err := json.Unmarshal(s.IncrementalState(), &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if _, ok := state.Objects["grew.txt"]; ok {
		t.Fatal("oversized changed object was checkpointed as complete")
	}
}
