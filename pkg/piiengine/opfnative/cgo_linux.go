//go:build opf_native && linux

package opfnative

// #cgo LDFLAGS: -L${SRCDIR}/cdeps/lib -Wl,--start-group -lpf -lggml -lggml-base -lggml-cpu -Wl,--end-group -lstdc++ -lm -lpthread -ldl -static-libstdc++ -static-libgcc
import "C"

// platformAutoDevice is what "" / "auto" resolves to on linux: CPU
// inference (the native release is built CPU-only, no CUDA).
const platformAutoDevice = "cpu"
