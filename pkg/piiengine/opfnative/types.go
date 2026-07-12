//go:build opf_native

package opfnative

import "errors"

// DefaultThreshold is pf_classify's score cutoff when Config.Threshold is
// unset. 0.5 matches the PoC and the subprocess engine's default.
const DefaultThreshold = 0.5

// Config configures a native privacy-filter.cpp engine.
type Config struct {
	// ModelPath is the GGUF weights file passed to pf_load.
	ModelPath string
	// Device is the pf_load device hint: "" / "auto" resolve to the
	// platform default (Metal on darwin, CPU on linux), "mps" maps to
	// "gpu"; "cpu" / "cuda" / "gpu" / "vulkan" pass through.
	Device string
	// Threshold is the per-entity score cutoff; <= 0 uses DefaultThreshold.
	Threshold float64
}

// Finding is field-identical to openaipf.Finding so the detector's adapter
// copy applies unchanged. BIOESTag is always "" — libpf resolves BIOES
// spans internally, so the Go side carries no token tag.
type Finding struct {
	EntityType string
	BIOESTag   string
	Start      int
	End        int
	Score      float64
	Text       string
}

var (
	ErrEmptyModelPath = errors.New("opfnative: model path is empty")
	ErrLoadFailed     = errors.New("opfnative: pf_load failed")
	ErrClosed         = errors.New("opfnative: engine closed")
	ErrClassify       = errors.New("opfnative: pf_classify failed")
	ErrChecksum       = errors.New("opfnative: model checksum mismatch")
	ErrUnknownVariant = errors.New("opfnative: unknown model variant")
)
