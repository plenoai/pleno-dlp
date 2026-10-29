package crash

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"regexp"
	"strings"
)

// ModulePath is the import-path prefix that marks an in-module frame.
const ModulePath = "github.com/plenoai/pleno-dlp/"

// fingerprintFrames is how many in-module frames identify a crash site.
const fingerprintFrames = 5

// selfPath frames (Recover's deferred handler) appear in every recovered
// stack and would only dilute the crash-site signal.
var selfPath = reflect.TypeOf(Report{}).PkgPath() + "."

var (
	digitsRe   = regexp.MustCompile(`[0-9]+`)
	frameArgRe = regexp.MustCompile(`\(.*\)\s*$`)
)

// Fingerprint groups crashes by cause independent of version, line numbers,
// and per-run values: sha256 over the digit-normalized message plus the top
// in-module function names, truncated to 16 hex chars.
func Fingerprint(message, stack string) string {
	h := sha256.New()
	h.Write([]byte(digitsRe.ReplaceAllString(message, "N")))
	for _, fn := range moduleFrames(stack, fingerprintFrames) {
		h.Write([]byte{'\n'})
		h.Write([]byte(fn))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// moduleFrames returns up to n function names (arguments stripped) of frames
// inside ModulePath, in stack order.
func moduleFrames(stack string, n int) []string {
	var out []string
	for _, line := range strings.Split(stack, "\n") {
		if line == "" || line[0] == '\t' || line[0] == ' ' || !strings.HasPrefix(line, ModulePath) ||
			strings.HasPrefix(line, selfPath) {
			continue
		}
		out = append(out, frameArgRe.ReplaceAllString(line, ""))
		if len(out) == n {
			break
		}
	}
	return out
}
