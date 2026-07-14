package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/bench/git-history/fixture"
)

const (
	schemaVersion      = 1
	competitiveLimit   = 0.90
	tailStabilityLimit = 0.90
	stabilityWindows   = 3
)

type benchmarkResult struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   string        `json:"generated_at"`
	Environment   environment   `json:"environment"`
	Configuration configuration `json:"configuration"`
	Fixture       fixtureResult `json:"fixture"`
	Source        sourceResult  `json:"source"`
	Tools         []toolResult  `json:"tools"`
	Gates         gateResult    `json:"gates"`
}

type environment struct {
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	GoVersion  string `json:"go_version"`
	GOMAXPROCS int    `json:"gomaxprocs"`
}

type configuration struct {
	Commits               int     `json:"commits"`
	FileSlots             int     `json:"file_slots"`
	Window                int     `json:"window"`
	Warmups               int     `json:"warmups"`
	Runs                  int     `json:"runs"`
	MinimumSampleSeconds  float64 `json:"minimum_sample_seconds"`
	CommandTimeoutSeconds float64 `json:"command_timeout_seconds"`
	Enforce               bool    `json:"enforce"`
}

type fixtureResult struct {
	Head          string            `json:"head"`
	Files         int               `json:"files"`
	CanaryCommit  string            `json:"canary_commit"`
	CanaryPath    string            `json:"canary_path"`
	CanaryOrdinal int               `json:"canary_ordinal"`
	Inventory     fixture.Inventory `json:"inventory"`
}

type sourceResult struct {
	Chunks               int            `json:"chunks"`
	Bytes                int64          `json:"bytes"`
	Seconds              float64        `json:"seconds"`
	WindowSize           int            `json:"window_size"`
	Windows              []sourceWindow `json:"windows"`
	StabilityWindows     int            `json:"stability_windows"`
	EarlyWindowStart     int            `json:"early_window_start_chunk"`
	EarlyWindowEnd       int            `json:"early_window_end_chunk"`
	TailWindowStart      int            `json:"tail_window_start_chunk"`
	TailWindowEnd        int            `json:"tail_window_end_chunk"`
	EarlyMedianCPS       float64        `json:"early_median_chunks_per_second"`
	TailMedianCPS        float64        `json:"tail_median_chunks_per_second"`
	TailEarlyRatio       float64        `json:"tail_early_ratio"`
	ThroughputSlope      float64        `json:"throughput_slope_chunks_per_second_per_window"`
	ScalingPrefixChunks  int            `json:"scaling_prefix_chunks"`
	ScalingPrefixSeconds float64        `json:"scaling_prefix_window_seconds"`
	FullWindowSeconds    float64        `json:"full_window_seconds"`
	FullToPrefixRatio    float64        `json:"full_to_prefix_time_ratio"`
	CanaryChunks         int            `json:"canary_chunks"`
	HeapAllocBytes       uint64         `json:"heap_alloc_bytes"`
	SysBytes             uint64         `json:"sys_bytes"`
	TotalAllocBytes      uint64         `json:"total_alloc_bytes"`
	GCCycles             uint32         `json:"gc_cycles"`
}

type sourceWindow struct {
	EndChunk        int     `json:"end_chunk"`
	Seconds         float64 `json:"seconds"`
	ChunksPerSecond float64 `json:"chunks_per_second"`
}

type toolResult struct {
	Name                  string    `json:"name"`
	Version               string    `json:"version"`
	BinarySHA256          string    `json:"binary_sha256"`
	WarmupSeconds         []float64 `json:"warmup_seconds"`
	IterationsPerSample   int       `json:"minimum_iterations_per_sample"`
	SampleIterations      []int     `json:"sample_iterations"`
	SampleWallSeconds     []float64 `json:"sample_wall_seconds"`
	SamplesSeconds        []float64 `json:"per_scan_seconds"`
	MedianSeconds         float64   `json:"median_seconds"`
	MinSeconds            float64   `json:"min_seconds"`
	MaxSeconds            float64   `json:"max_seconds"`
	CanaryFindingsPerScan int       `json:"canary_findings_per_scan"`
}

type gateResult struct {
	Enforced               bool    `json:"enforced"`
	CompetitiveLimit       float64 `json:"competitive_limit"`
	PlenoToTrufflehogRatio float64 `json:"pleno_to_trufflehog_ratio"`
	CompetitivePass        bool    `json:"competitive_pass"`
	TailStabilityLimit     float64 `json:"tail_stability_limit"`
	TailEarlyRatio         float64 `json:"tail_early_ratio"`
	TailStabilityPass      bool    `json:"tail_stability_pass"`
	Pass                   bool    `json:"pass"`
}

func newResult(opts options, meta fixture.Metadata, source sourceResult, tools []toolResult) benchmarkResult {
	pleno := toolByName(tools, "pleno-dlp")
	trufflehog := toolByName(tools, "trufflehog")
	ratio := pleno.MedianSeconds / trufflehog.MedianSeconds
	gates := gateResult{
		Enforced:               opts.enforce,
		CompetitiveLimit:       competitiveLimit,
		PlenoToTrufflehogRatio: ratio,
		CompetitivePass:        ratio <= competitiveLimit,
		TailStabilityLimit:     tailStabilityLimit,
		TailEarlyRatio:         source.TailEarlyRatio,
		TailStabilityPass:      source.TailEarlyRatio >= tailStabilityLimit,
	}
	gates.Pass = gates.CompetitivePass && gates.TailStabilityPass
	return benchmarkResult{
		SchemaVersion: schemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Environment: environment{
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
			GoVersion: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0),
		},
		Configuration: configuration{
			Commits: opts.commits, FileSlots: opts.files, Window: opts.window,
			Warmups: opts.warmups, Runs: opts.runs,
			MinimumSampleSeconds:  opts.minSample.Seconds(),
			CommandTimeoutSeconds: opts.commandTimeout.Seconds(), Enforce: opts.enforce,
		},
		Fixture: fixtureResult{
			Head: meta.Head, Files: min(opts.commits, opts.files), CanaryCommit: meta.CanaryCommit, CanaryPath: meta.CanaryPath,
			CanaryOrdinal: meta.CanaryOrdinal, Inventory: meta.Inventory,
		},
		Source: source,
		Tools:  tools,
		Gates:  gates,
	}
}

func toolByName(tools []toolResult, name string) toolResult {
	for _, tool := range tools {
		if tool.Name == name {
			return tool
		}
	}
	panic("missing tool result: " + name)
}

func writeResults(jsonPath, markdownPath string, result benchmarkResult) error {
	for _, path := range []string{jsonPath, markdownPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
		return err
	}
	return os.WriteFile(markdownPath, []byte(renderMarkdown(result)), 0o644)
}

func renderMarkdown(result benchmarkResult) string {
	var out strings.Builder
	fmt.Fprintln(&out, "# Git history benchmark")
	fmt.Fprintln(&out)
	fmt.Fprintf(&out, "Generated: `%s`  \n", result.GeneratedAt)
	fmt.Fprintf(&out, "Fixture: %d commits, %d files, %d objects, %s pack  \n",
		result.Configuration.Commits, result.Fixture.Files, result.Fixture.Inventory.Total, formatBytes(result.Fixture.Inventory.PackBytes))
	fmt.Fprintf(&out, "Canary: commit `%s`, path `%s` (one finding per scan)\n\n", result.Fixture.CanaryCommit, result.Fixture.CanaryPath)
	fmt.Fprintln(&out, "## End-to-end")
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "| Tool | Version | Median/scan | Min-max | Sample wall | Scans/sample | Canary findings |")
	fmt.Fprintln(&out, "|---|---|---:|---:|---:|---:|---:|")
	for _, tool := range result.Tools {
		wallMin, wallMax := minMax(tool.SampleWallSeconds)
		iterationMin, iterationMax := intMinMax(tool.SampleIterations)
		fmt.Fprintf(&out, "| %s | %s | %.3f s | %.3f-%.3f s | %.3f-%.3f s | %d-%d | %d |\n",
			tool.Name, markdownCell(tool.Version), tool.MedianSeconds, tool.MinSeconds, tool.MaxSeconds,
			wallMin, wallMax, iterationMin, iterationMax, tool.CanaryFindingsPerScan)
	}
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "## Source windows")
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "| End chunk | Window | Throughput |")
	fmt.Fprintln(&out, "|---:|---:|---:|")
	for _, window := range result.Source.Windows {
		fmt.Fprintf(&out, "| %d | %.3f s | %.1f chunks/s |\n", window.EndChunk, window.Seconds, window.ChunksPerSecond)
	}
	fmt.Fprintf(&out, "\nLinear throughput slope: `%.1f chunks/s/window`. Stability uses %d-window medians: early chunks %d-%d = %.1f chunks/s; tail chunks %d-%d = %.1f chunks/s; tail/early = `%.3f`.\n",
		result.Source.ThroughputSlope, result.Source.StabilityWindows,
		result.Source.EarlyWindowStart, result.Source.EarlyWindowEnd, result.Source.EarlyMedianCPS,
		result.Source.TailWindowStart, result.Source.TailWindowEnd, result.Source.TailMedianCPS,
		result.Source.TailEarlyRatio)
	fmt.Fprintf(&out, "Source scaling: %d-chunk prefix = %.3f s; all %d chunks = %.3f s; full/prefix = `%.3f`.\n",
		result.Source.ScalingPrefixChunks, result.Source.ScalingPrefixSeconds, result.Source.Chunks,
		result.Source.FullWindowSeconds, result.Source.FullToPrefixRatio)
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "## Gates")
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "| Gate | Result | Threshold | Pass |")
	fmt.Fprintln(&out, "|---|---:|---:|:---:|")
	fmt.Fprintf(&out, "| pleno / TruffleHog median | %.3f | <= %.2f | %s |\n",
		result.Gates.PlenoToTrufflehogRatio, result.Gates.CompetitiveLimit, passMark(result.Gates.CompetitivePass))
	fmt.Fprintf(&out, "| tail / early throughput | %.3f | >= %.2f | %s |\n",
		result.Gates.TailEarlyRatio, result.Gates.TailStabilityLimit, passMark(result.Gates.TailStabilityPass))
	fmt.Fprintln(&out)
	fmt.Fprintf(&out, "Threshold enforcement: `%t`; overall pass: `%t`.\n", result.Gates.Enforced, result.Gates.Pass)
	return out.String()
}

func passMark(pass bool) string {
	if pass {
		return "yes"
	}
	return "no"
}

func markdownCell(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func formatBytes(value int64) string {
	const mib = 1024 * 1024
	if value < mib {
		return fmt.Sprintf("%d B", value)
	}
	return fmt.Sprintf("%.1f MiB", float64(value)/mib)
}

func intMinMax(values []int) (int, int) {
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
