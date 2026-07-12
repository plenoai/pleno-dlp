//go:build opf_native && darwin

package opfnative

// #cgo LDFLAGS: -L${SRCDIR}/cdeps/lib -lpf -lggml -lggml-base -lggml-cpu -lggml-blas -lggml-metal -lc++ -framework Foundation -framework Metal -framework MetalKit -framework Accelerate -framework CoreFoundation
import "C"

// platformAutoDevice is what "" / "auto" resolves to on darwin: the Metal
// backend, exposed to pf_load as "gpu".
const platformAutoDevice = "gpu"
