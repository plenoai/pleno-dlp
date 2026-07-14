package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/bench/git-history/fixture"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	gitsource "github.com/plenoai/pleno-dlp/pkg/sources/git"
)

func measureSource(ctx context.Context, meta fixture.Metadata, windowSize int) (sourceResult, error) {
	raw, err := json.Marshal(gitsource.Config{Repo: meta.Repo, Branch: "main"})
	if err != nil {
		return sourceResult{}, err
	}
	src := &gitsource.Source{}
	if err := src.Init(ctx, "git-history-benchmark", 0, 1, false, raw, 1); err != nil {
		return sourceResult{}, err
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	out := make(chan *sources.Chunk, 4)
	errCh := make(chan error, 1)
	started := time.Now()
	go func() {
		errCh <- src.Chunks(ctx, out)
		close(out)
	}()

	result := sourceResult{WindowSize: windowSize}
	windowStarted := started
	for chunk := range out {
		result.Chunks++
		result.Bytes += int64(len(chunk.Data))
		if bytes.Contains(chunk.Data, []byte(meta.Canary)) {
			result.CanaryChunks++
		}
		if result.Chunks%windowSize == 0 {
			now := time.Now()
			seconds := now.Sub(windowStarted).Seconds()
			result.Windows = append(result.Windows, sourceWindow{
				EndChunk:        result.Chunks,
				Seconds:         seconds,
				ChunksPerSecond: float64(windowSize) / seconds,
			})
			windowStarted = now
		}
	}
	if err := <-errCh; err != nil {
		return sourceResult{}, err
	}
	result.Seconds = time.Since(started).Seconds()
	if result.Chunks != meta.Inventory.Commits {
		return sourceResult{}, fmt.Errorf("source emitted %d chunks, want %d", result.Chunks, meta.Inventory.Commits)
	}
	if result.CanaryChunks != 1 {
		return sourceResult{}, fmt.Errorf("source emitted canary in %d chunks, want 1", result.CanaryChunks)
	}
	minimumWindows := 1 + 2*stabilityWindows
	if len(result.Windows) < minimumWindows {
		return sourceResult{}, fmt.Errorf("source measurement produced %d windows, need at least %d", len(result.Windows), minimumWindows)
	}
	early := result.Windows[1 : 1+stabilityWindows]
	tail := result.Windows[len(result.Windows)-stabilityWindows:]
	result.StabilityWindows = stabilityWindows
	result.EarlyWindowStart = early[0].EndChunk - windowSize + 1
	result.EarlyWindowEnd = early[len(early)-1].EndChunk
	result.TailWindowStart = tail[0].EndChunk - windowSize + 1
	result.TailWindowEnd = tail[len(tail)-1].EndChunk
	result.EarlyMedianCPS = medianWindowThroughput(early)
	result.TailMedianCPS = medianWindowThroughput(tail)
	result.TailEarlyRatio = result.TailMedianCPS / result.EarlyMedianCPS
	result.ThroughputSlope = linearSlope(result.Windows[1:])
	half := len(result.Windows) / 2
	result.ScalingPrefixChunks = result.Windows[half-1].EndChunk
	result.ScalingPrefixSeconds = sumWindowSeconds(result.Windows[:half])
	result.FullWindowSeconds = sumWindowSeconds(result.Windows)
	result.FullToPrefixRatio = result.FullWindowSeconds / result.ScalingPrefixSeconds
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	result.HeapAllocBytes = after.HeapAlloc
	result.SysBytes = after.Sys
	result.TotalAllocBytes = after.TotalAlloc - before.TotalAlloc
	result.GCCycles = after.NumGC - before.NumGC
	return result, nil
}

type toolSpec struct {
	name      string
	bin       string
	args      []string
	allowExit map[int]bool
	parse     func([]byte, fixture.Metadata) (canaryObservation, error)
}

type canaryObservation struct {
	Total   int
	Matches int
	File    string
	Commit  string
}

func measureEndToEnd(ctx context.Context, meta fixture.Metadata, opts options, plenoBin string) ([]toolResult, error) {
	pleno := toolSpec{
		name: "pleno-dlp",
		bin:  plenoBin,
		args: []string{
			"scan", "--no-verify", "--pii-engine", "off", "--include-detectors", "GitHub",
			"--format", "json", "--quiet", "--concurrency", "8",
			"git", "--repo", meta.Repo, "--branch", "main",
		},
		allowExit: map[int]bool{0: true, 1: true},
		parse:     parsePlenoCanary,
	}
	trufflehog := toolSpec{
		name: "trufflehog",
		bin:  opts.trufflehogBin,
		args: []string{
			"git", "--no-update", "--no-verification", "--json", "--log-level=-1",
			"--force-skip-binaries", "--force-skip-archives", "--include-detectors=github",
			"--concurrency=8", "--bare", "--branch", "main", "file://" + meta.Repo,
		},
		allowExit: map[int]bool{0: true},
		parse:     parseTruffleCanary,
	}
	specs := []*toolSpec{&pleno, &trufflehog}
	results := map[string]*toolResult{}

	for _, spec := range specs {
		result := &toolResult{Name: spec.name}
		result.Version = toolVersion(spec)
		hash, err := fileSHA256(spec.bin)
		if err != nil {
			return nil, err
		}
		result.BinarySHA256 = hash
		results[spec.name] = result
	}

	for round := 0; round < opts.warmups; round++ {
		order := specs
		if round%2 == 1 {
			order = []*toolSpec{&trufflehog, &pleno}
		}
		for _, spec := range order {
			seconds, _, _, err := runToolBatch(ctx, *spec, meta, 1, 0, opts.commandTimeout)
			if err != nil {
				return nil, fmt.Errorf("%s warmup: %w", spec.name, err)
			}
			results[spec.name].WarmupSeconds = append(results[spec.name].WarmupSeconds, seconds)
		}
	}
	for _, spec := range specs {
		result := results[spec.name]
		result.IterationsPerSample = int(math.Ceil(opts.minSample.Seconds() / median(result.WarmupSeconds)))
		if result.IterationsPerSample < 1 {
			result.IterationsPerSample = 1
		}
		fmt.Fprintf(os.Stderr, "git-history-bench: %s warmup median %.3fs, %d scan(s)/sample\n", spec.name, median(result.WarmupSeconds), result.IterationsPerSample)
	}

	orders := [][]*toolSpec{
		{&pleno, &trufflehog, &trufflehog, &pleno},
		{&trufflehog, &pleno, &pleno, &trufflehog},
	}
	for round := 0; len(results[pleno.name].SamplesSeconds) < opts.runs || len(results[trufflehog.name].SamplesSeconds) < opts.runs; round++ {
		for _, spec := range orders[round%len(orders)] {
			result := results[spec.name]
			if len(result.SamplesSeconds) >= opts.runs {
				continue
			}
			seconds, wallSeconds, iterations, err := runToolBatch(ctx, *spec, meta, result.IterationsPerSample, opts.minSample, opts.commandTimeout)
			if err != nil {
				return nil, fmt.Errorf("%s sample %d: %w", spec.name, len(result.SamplesSeconds)+1, err)
			}
			perScan := seconds / float64(iterations)
			result.SampleWallSeconds = append(result.SampleWallSeconds, wallSeconds)
			result.SampleIterations = append(result.SampleIterations, iterations)
			result.SamplesSeconds = append(result.SamplesSeconds, perScan)
			fmt.Fprintf(os.Stderr, "git-history-bench: %s sample %d/%d %.3fs/scan (%d scans, %.3fs sample wall)\n", spec.name, len(result.SamplesSeconds), opts.runs, perScan, iterations, wallSeconds)
		}
	}

	out := make([]toolResult, 0, len(specs))
	for _, spec := range specs {
		result := results[spec.name]
		result.MedianSeconds = median(result.SamplesSeconds)
		result.MinSeconds, result.MaxSeconds = minMax(result.SamplesSeconds)
		result.CanaryFindingsPerScan = 1
		out = append(out, *result)
	}
	return out, nil
}

func runToolBatch(ctx context.Context, spec toolSpec, meta fixture.Metadata, minimumIterations int, minimumDuration, timeout time.Duration) (float64, float64, int, error) {
	var total time.Duration
	iterations := 0
	batchStarted := time.Now()
	for iterations < minimumIterations || time.Since(batchStarted) < minimumDuration {
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		cmd := exec.CommandContext(runCtx, spec.bin, spec.args...)
		stdout, err := cmd.Output()
		elapsed := time.Since(started)
		ctxErr := runCtx.Err()
		cancel()
		if ctxErr != nil {
			return 0, 0, 0, ctxErr
		}
		exitCode := 0
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				return 0, 0, 0, err
			}
			exitCode = exitErr.ExitCode()
			if !spec.allowExit[exitCode] {
				return 0, 0, 0, fmt.Errorf("exit %d: %s", exitCode, truncate(string(exitErr.Stderr), 4096))
			}
		}
		observation, err := spec.parse(stdout, meta)
		if err != nil {
			return 0, 0, 0, err
		}
		if observation.Total != 1 || observation.Matches != 1 || observation.File != meta.CanaryPath || observation.Commit != meta.CanaryCommit {
			return 0, 0, 0, fmt.Errorf("canary observation=%+v want total=1 matches=1 file=%q commit=%q", observation, meta.CanaryPath, meta.CanaryCommit)
		}
		total += elapsed
		iterations++
	}
	return total.Seconds(), time.Since(batchStarted).Seconds(), iterations, nil
}

func parsePlenoCanary(data []byte, meta fixture.Metadata) (canaryObservation, error) {
	var records []struct {
		Detector   string `json:"detector"`
		SecretHash string `json:"secret_hash"`
		Source     struct {
			Metadata map[string]any `json:"metadata"`
		} `json:"source"`
	}
	if err := json.Unmarshal(data, &records); err != nil {
		return canaryObservation{}, err
	}
	wantHash := sha256.Sum256([]byte(meta.Canary))
	observation := canaryObservation{Total: len(records)}
	for _, record := range records {
		if !strings.EqualFold(record.Detector, "github") || record.SecretHash != hex.EncodeToString(wantHash[:]) {
			continue
		}
		observation.Matches++
		observation.File, _ = record.Source.Metadata["file"].(string)
		observation.Commit, _ = record.Source.Metadata["commit"].(string)
	}
	return observation, nil
}

func parseTruffleCanary(data []byte, meta fixture.Metadata) (canaryObservation, error) {
	observation := canaryObservation{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record struct {
			DetectorName   string `json:"DetectorName"`
			Raw            string `json:"Raw"`
			RawV2          string `json:"RawV2"`
			SourceMetadata struct {
				Data map[string]json.RawMessage `json:"Data"`
			} `json:"SourceMetadata"`
		}
		if err := json.Unmarshal(line, &record); err != nil {
			return canaryObservation{}, err
		}
		if record.DetectorName == "" {
			continue
		}
		observation.Total++
		if !strings.EqualFold(record.DetectorName, "github") || (!encodedValueMatches(record.Raw, meta.Canary) && !encodedValueMatches(record.RawV2, meta.Canary)) {
			continue
		}
		observation.Matches++
		for key, raw := range record.SourceMetadata.Data {
			if !strings.EqualFold(key, "git") {
				continue
			}
			var gitMeta struct {
				Commit string `json:"commit"`
				File   string `json:"file"`
			}
			if err := json.Unmarshal(raw, &gitMeta); err != nil {
				return canaryObservation{}, err
			}
			observation.Commit = gitMeta.Commit
			observation.File = gitMeta.File
		}
	}
	if err := scanner.Err(); err != nil {
		return canaryObservation{}, err
	}
	return observation, nil
}

func encodedValueMatches(value, want string) bool {
	if value == want {
		return true
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && string(decoded) == want
}

func toolVersion(spec *toolSpec) string {
	out, err := exec.Command(spec.bin, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func median(values []float64) float64 {
	copyOf := append([]float64(nil), values...)
	sort.Float64s(copyOf)
	middle := len(copyOf) / 2
	if len(copyOf)%2 == 1 {
		return copyOf[middle]
	}
	return (copyOf[middle-1] + copyOf[middle]) / 2
}

func minMax(values []float64) (float64, float64) {
	minimum, maximum := values[0], values[0]
	for _, value := range values[1:] {
		if value < minimum {
			minimum = value
		}
		if value > maximum {
			maximum = value
		}
	}
	return minimum, maximum
}

func linearSlope(windows []sourceWindow) float64 {
	var sumX, sumY, sumXY, sumXX float64
	for i, window := range windows {
		x := float64(i + 1)
		y := window.ChunksPerSecond
		sumX += x
		sumY += y
		sumXY += x * y
		sumXX += x * x
	}
	n := float64(len(windows))
	denominator := n*sumXX - sumX*sumX
	if denominator == 0 {
		return 0
	}
	return (n*sumXY - sumX*sumY) / denominator
}

func medianWindowThroughput(windows []sourceWindow) float64 {
	values := make([]float64, len(windows))
	for i, window := range windows {
		values[i] = window.ChunksPerSecond
	}
	return median(values)
}

func sumWindowSeconds(windows []sourceWindow) float64 {
	var total float64
	for _, window := range windows {
		total += window.Seconds
	}
	return total
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
