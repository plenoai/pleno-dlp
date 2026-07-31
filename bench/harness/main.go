// Command harness is the dlp-bench re-run harness (issue #298): it runs
// pleno-dlp (built from this checkout), trufflehog, and gitleaks against
// the synthetic corpus (bench/gen) and, unless skipped, leaky-repo, then
// writes bench/results/results.json + results.md. `make bench` is the
// documented entry point; see bench/README.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/plenoai/pleno-dlp/bench/labels"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

func run() error {
	syntheticDir := flag.String("synthetic-dir", "bench/fixtures/synthetic/generated", "generated synthetic corpus (run `go run ./bench/gen` first)")
	labelsPath := flag.String("labels", "bench/fixtures/synthetic/labels.json", "synthetic corpus ground-truth manifest")
	leakyRepoDir := flag.String("leaky-repo-dir", "bench/.cache/leaky-repo", "local checkout of the leaky-repo real-world corpus (cloned at a pinned commit if absent)")
	skipLeakyRepo := flag.Bool("skip-leaky-repo", false, "skip the leaky-repo real-world corpus (offline / no network)")
	outDir := flag.String("out", "bench/results", "directory for results.json / results.md")
	plenoDLPBin := flag.String("pleno-dlp-bin", "", "path to a pre-built pleno-dlp binary (default: go build fresh from this checkout)")
	trufflehogBin := flag.String("trufflehog-bin", "", "path to trufflehog (default: bench/.tools/trufflehog or $PATH)")
	gitleaksBin := flag.String("gitleaks-bin", "", "path to gitleaks (default: bench/.tools/gitleaks or $PATH)")
	flag.Parse()

	plenoDLP, cleanup, err := resolvePlenoDLP(*plenoDLPBin)
	if err != nil {
		return err
	}
	defer cleanup()

	trufflehog, err := resolveBinary(*trufflehogBin, "trufflehog", "make bench-tools")
	if err != nil {
		return err
	}
	gitleaks, err := resolveBinary(*gitleaksBin, "gitleaks", "make bench-tools")
	if err != nil {
		return err
	}

	versions := map[string]string{
		"pleno-dlp":  toolVersion(plenoDLP),
		"trufflehog": toolVersion(trufflehog),
		"gitleaks":   toolVersion(gitleaks),
	}
	warnIfVersionDrifted(trufflehog, versions["trufflehog"])
	warnIfVersionDrifted(gitleaks, versions["gitleaks"])

	var reports []corpusReport

	syntheticReport, err := scoreSyntheticCorpus(*syntheticDir, *labelsPath, plenoDLP, trufflehog, gitleaks)
	if err != nil {
		return fmt.Errorf("synthetic corpus: %w", err)
	}
	reports = append(reports, syntheticReport)

	if !*skipLeakyRepo {
		lrReport, err := scoreLeakyRepo(*leakyRepoDir, plenoDLP, trufflehog, gitleaks)
		if err != nil {
			return fmt.Errorf("leaky-repo corpus (pass -skip-leaky-repo to skip): %w", err)
		}
		reports = append(reports, lrReport)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	jsonBuf, err := marshalJSON(reports, versions)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "results.json"), jsonBuf, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "results.md"), []byte(renderMarkdown(reports, versions)), 0o644); err != nil {
		return err
	}

	for _, r := range reports {
		fmt.Printf("%s:\n", r.Corpus)
		for _, rec := range r.Tools {
			fmt.Printf("  %-10s %d/%d\n", rec.Tool, rec.Hit, rec.Total)
		}
	}
	fmt.Printf("wrote %s/results.json and %s/results.md\n", *outDir, *outDir)
	return nil
}

// resolvePlenoDLP builds a fresh binary from this checkout unless
// override is set. Building fresh (rather than resolving a released
// binary from $PATH) is deliberate: the whole point of this harness is
// measuring the code currently checked out, not whatever version
// happens to be installed — see bench/README.md's discussion of
// docs/comparison.md going stale as detectors are added (the
// asana-pat / azure-storage-account-key / pgp-private-key-block /
// slack-webhook-url misses it lists are already fixed on this branch).
func resolvePlenoDLP(override string) (path string, cleanup func(), err error) {
	noop := func() {}
	if override != "" {
		if _, statErr := os.Stat(override); statErr != nil {
			return "", noop, fmt.Errorf("resolvePlenoDLP: explicit path %q: %w", override, statErr)
		}
		return override, noop, nil
	}
	tmp, err := os.MkdirTemp("", "pleno-dlp-bench-*")
	if err != nil {
		return "", noop, err
	}
	bin := filepath.Join(tmp, "pleno-dlp")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/pleno-dlp")
	if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
		os.RemoveAll(tmp)
		return "", noop, fmt.Errorf("go build ./cmd/pleno-dlp: %w: %s", buildErr, out)
	}
	return bin, func() { os.RemoveAll(tmp) }, nil
}

// runOne invokes bin with args and returns stdout. Non-zero exit is not
// itself an error — pleno-dlp and gitleaks both exit non-zero when
// findings exist (see docs/comparison.md's "Exit-code gating" capability
// row) — so only an exec failure (binary missing, killed, etc.) is
// treated as fatal.
func runOne(bin string, args ...string) ([]byte, error) {
	cmd := exec.Command(bin, args...)
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return out, nil
		}
		return nil, fmt.Errorf("%s %v: %w", bin, args, err)
	}
	return out, nil
}

func scoreSyntheticCorpus(dir, labelsPath, plenoDLP, trufflehog, gitleaks string) (corpusReport, error) {
	raw, err := os.ReadFile(labelsPath)
	if err != nil {
		return corpusReport{}, fmt.Errorf("read labels (run `go run ./bench/gen` first): %w", err)
	}
	var entries []labels.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return corpusReport{}, fmt.Errorf("parse labels.json: %w", err)
	}
	groundTruth := make([]string, 0, len(entries))
	knownMiss := make(map[string]string, len(entries))
	for _, e := range entries {
		groundTruth = append(groundTruth, e.File)
		if e.KnownMiss != "" {
			knownMiss[e.File] = e.KnownMiss
		}
	}

	findings, err := runAllTools(dir, plenoDLP, trufflehog, gitleaks)
	if err != nil {
		return corpusReport{}, err
	}
	rows, recalls := scoreFiles(groundTruth, knownMiss, findings)
	return corpusReport{Corpus: "synthetic (docs/comparison.md §2 equivalent)", Tools: recalls, Rows: rows}, nil
}

func scoreLeakyRepo(dir, plenoDLP, trufflehog, gitleaks string) (corpusReport, error) {
	if err := ensureLeakyRepo(dir); err != nil {
		return corpusReport{}, err
	}
	groundTruth, err := parseLeakyRepoGroundTruth(dir)
	if err != nil {
		return corpusReport{}, err
	}
	findings, err := runAllTools(dir, plenoDLP, trufflehog, gitleaks)
	if err != nil {
		return corpusReport{}, err
	}
	rows, recalls := scoreFiles(groundTruth, nil, findings)
	return corpusReport{Corpus: fmt.Sprintf("leaky-repo@%s (docs/comparison.md §3 equivalent)", leakyRepoCommit[:12]), Tools: recalls, Rows: rows}, nil
}

// runAllTools runs the three canonical invocations from
// docs/comparison.md's "Versions and environment" section against dir
// and parses each into the common finding shape.
func runAllTools(dir, plenoDLP, trufflehog, gitleaks string) (map[string][]finding, error) {
	out := make(map[string][]finding, 3)

	pOut, err := runOne(plenoDLP, plenoDetectionOnlyArgs(dir)...)
	if err != nil {
		return nil, fmt.Errorf("pleno-dlp: %w", err)
	}
	pFindings, err := parsePlenoDLP(pOut)
	if err != nil {
		return nil, fmt.Errorf("pleno-dlp: %w", err)
	}
	out["pleno-dlp"] = pFindings

	tOut, err := runOne(trufflehog, "filesystem", dir, "--no-verification", "--no-update", "--json", "--log-level=-1")
	if err != nil {
		return nil, fmt.Errorf("trufflehog: %w", err)
	}
	tFindings, err := parseTrufflehog(tOut)
	if err != nil {
		return nil, fmt.Errorf("trufflehog: %w", err)
	}
	out["trufflehog"] = tFindings

	gReportPath := filepath.Join(os.TempDir(), fmt.Sprintf("dlp-bench-gitleaks-%d.json", os.Getpid()))
	defer os.Remove(gReportPath)
	if _, err := runOne(gitleaks, "dir", dir, "--no-banner", "--report-format", "json", "--report-path", gReportPath, "--exit-code", "0"); err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}
	gOut, err := os.ReadFile(gReportPath)
	if err != nil {
		return nil, fmt.Errorf("gitleaks: read report: %w", err)
	}
	gFindings, err := parseGitleaks(gOut)
	if err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}
	out["gitleaks"] = gFindings

	return out, nil
}

func plenoDetectionOnlyArgs(dir string) []string {
	return []string{
		"scan", "filesystem", dir,
		"--no-verify",
		"--quiet",
		"--format", "json",
	}
}
