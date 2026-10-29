package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	piiAnonymize "github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

const feedbackPIIRedactionBudget = 2 * time.Second

var errFeedbackPIIUnavailable = errors.New("feedback: selected PII engine is unavailable; report was not saved or sent")
var feedbackPIISelector = selectFeedbackPII

type feedbackPIISelection struct {
	Detector detectors.Detector
	Stop     func()
	Engine   string
}

func feedbackPIISettings() piiEngineSettings {
	return piiEngineSettings{
		mode:           feedbackOpts.piiEngine,
		command:        feedbackOpts.piiEngineCmd,
		port:           feedbackOpts.piiEnginePort,
		language:       feedbackOpts.piiEngineLanguage,
		readyTimeout:   feedbackOpts.piiEngineReady,
		requestTimeout: feedbackOpts.piiEngineRequest,
		device:         feedbackOpts.piiEngineDevice,
		model:          feedbackOpts.piiModel,
		modelPath:      feedbackOpts.piiModelPath,
	}
}

func selectFeedbackPII(ctx context.Context) (feedbackPIISelection, error) {
	settings := feedbackPIISettings()
	mode := strings.ToLower(strings.TrimSpace(settings.mode))
	switch mode {
	case "off":
		return feedbackPIISelection{}, nil
	case "auto":
		return selectCachedFeedbackPII(ctx, settings)
	case "anonymize", "openai-pf-native":
		settings.mode = mode
		stop, err := startPIIEngineWithSettings(ctx, settings, io.Discard)
		if err != nil {
			return feedbackPIISelection{}, errFeedbackPIIUnavailable
		}
		selected, err := feedbackPIISelectionFor(mode, stop)
		if err != nil {
			if stop != nil {
				stop()
			}
			return feedbackPIISelection{}, err
		}
		return selected, nil
	default:
		return feedbackPIISelection{}, errors.New("feedback: invalid --pii-engine (want auto, off, anonymize, or openai-pf-native)")
	}
}

func selectCachedFeedbackPII(ctx context.Context, settings piiEngineSettings) (feedbackPIISelection, error) {
	if settings.modelPath != "" {
		modelPath, available, err := cachedOpenAIPFModelPath(settings)
		if err != nil || !available {
			return feedbackPIISelection{}, errFeedbackPIIUnavailable
		}
		settings.mode = "openai-pf-native"
		settings.modelPath = modelPath
		stop, err := startOpenAIPFNativeWithSettings(ctx, settings, io.Discard)
		if err != nil {
			return feedbackPIISelection{}, errFeedbackPIIUnavailable
		}
		return startedFeedbackPIISelection("openai-pf-native", stop)
	}

	activeAnonymize := piiAnonymize.Default() != nil
	activeNative := feedbackOpenAIPFActive()
	if activeAnonymize && activeNative {
		return feedbackPIISelection{}, errors.New("feedback: multiple PII engines are active; report was not saved or sent")
	}
	if activeAnonymize {
		return feedbackPIISelectionFor("anonymize", nil)
	}
	if activeNative {
		return feedbackPIISelectionFor("openai-pf-native", nil)
	}

	if uvPath, cacheDir, available := cachedAnonymizeRuntime(); available {
		settings.mode = "anonymize"
		settings.env = cachedAnonymizeEnv()
		argv := cachedAnonymizeArgv(uvPath, cacheDir)
		stop, err := startAnonymizeWithArgv(ctx, settings, argv, io.Discard)
		if err != nil {
			return feedbackPIISelection{}, errFeedbackPIIUnavailable
		}
		return startedFeedbackPIISelection("anonymize", stop)
	}

	settings.mode = "openai-pf-native"
	modelPath, available, err := cachedOpenAIPFModelPath(settings)
	if err != nil {
		return feedbackPIISelection{}, errFeedbackPIIUnavailable
	}
	if available {
		settings.modelPath = modelPath
		stop, err := startOpenAIPFNativeWithSettings(ctx, settings, io.Discard)
		if err != nil {
			return feedbackPIISelection{}, errFeedbackPIIUnavailable
		}
		return startedFeedbackPIISelection("openai-pf-native", stop)
	}
	return feedbackPIISelection{}, nil
}

func feedbackPIISelectionFor(engine string, stop func()) (feedbackPIISelection, error) {
	typ := detectors.PIIAnonymize
	if engine == "openai-pf-native" {
		typ = detectors.PIIOpenAIPF
	}
	for _, d := range detectors.All() {
		if d.Type() == typ {
			return feedbackPIISelection{Detector: d, Stop: stop, Engine: engine}, nil
		}
	}
	return feedbackPIISelection{}, errors.New("feedback: selected PII detector is unavailable; report was not saved or sent")
}

func startedFeedbackPIISelection(engine string, stop func()) (feedbackPIISelection, error) {
	selected, err := feedbackPIISelectionFor(engine, stop)
	if err != nil && stop != nil {
		stop()
	}
	return selected, err
}

func feedbackRedactor(getenv func(string) string, home string) *crash.Redactor {
	allDetectors := detectors.All()
	secretDetectors := make([]detectors.Detector, 0, len(allDetectors))
	for _, d := range allDetectors {
		if d.Type() == detectors.PIIAnonymize || d.Type() == detectors.PIIOpenAIPF {
			continue
		}
		secretDetectors = append(secretDetectors, d)
	}
	return &crash.Redactor{
		Prefixes:  crash.EnvPrefixes(getenv, home),
		Detectors: secretDetectors,
	}
}

func redactFeedbackValue(ctx context.Context, red *crash.Redactor, pii detectors.Detector, text string) (string, error) {
	return redactFeedbackValueWithin(ctx, red, pii, text, feedbackPIIRedactionBudget)
}

func redactFeedbackValueWithin(ctx context.Context, red *crash.Redactor, pii detectors.Detector, text string, budget time.Duration) (string, error) {
	if pii == nil {
		return red.Redact(text), nil
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	redacted, err := red.RedactWithPII(ctx, text, pii)
	if err != nil {
		return "", errors.New("feedback: PII redaction failed; report was not saved or sent")
	}
	return redacted, nil
}

func cachedAnonymizeRuntime() (uvPath, cacheDir string, available bool) {
	uvPath, err := exec.LookPath(uvBin)
	if err != nil {
		return "", "", false
	}
	cacheDir, err = resolveCacheDir("")
	if err != nil || !cachedAnonymizeRuntimeAvailable(uvPath, cacheDir) || !isPinnedPIIServerCache(cacheDir) {
		return "", "", false
	}
	return uvPath, cacheDir, true
}

func cachedAnonymizeRuntimeAvailable(uvPath, cacheDir string) bool {
	if uvPath == "" {
		return false
	}
	if _, err := os.Stat(uvPath); err != nil {
		return false
	}
	for _, dir := range []string{filepath.Join(cacheDir, ".git"), filepath.Join(cacheDir, ".venv")} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return false
		}
	}
	for _, file := range []string{
		filepath.Join(cacheDir, "pyproject.toml"),
		filepath.Join(cacheDir, "uv.lock"),
		filepath.Join(cacheDir, ".venv", "pyvenv.cfg"),
		filepath.Join(cacheDir, "server", "src", "app.py"),
	} {
		info, err := os.Stat(file)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return cachedAnonymizeModelsAvailable(filepath.Join(cacheDir, ".venv"))
}

func cachedAnonymizeModelsAvailable(venvDir string) bool {
	sites := []string{filepath.Join(venvDir, "Lib", "site-packages")}
	entries, err := os.ReadDir(filepath.Join(venvDir, "lib"))
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "python") {
				sites = append(sites, filepath.Join(venvDir, "lib", entry.Name(), "site-packages"))
			}
		}
	}
	models := []string{"spacy", "en_core_web_sm", "pleno_anonymize_ja", "pleno_anonymize_en"}
	for _, model := range models {
		found := false
		for _, site := range sites {
			info, err := os.Stat(filepath.Join(site, model))
			if err == nil && info.IsDir() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func cachedAnonymizeEnv() []string {
	return []string{
		"HF_HUB_OFFLINE=1",
		"TRANSFORMERS_OFFLINE=1",
		"HF_HUB_DISABLE_TELEMETRY=1",
	}
}

func cachedAnonymizeArgv(uvPath, cacheDir string) []string {
	return []string{
		uvPath, "--offline", "run", "--directory", cacheDir, "--no-sync",
		"--package", "pleno-anonymize-server", "uvicorn", "server.src.app:app",
		"--host", "127.0.0.1", "--port", "{PORT}",
	}
}
