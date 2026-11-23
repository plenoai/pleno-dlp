package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// fingerprintVersion is mixed into every fingerprint so a future change to
// the inputs produces disjoint values instead of silently colliding.
const fingerprintVersion = "pleno-dlp/fingerprint/v1"

// Fingerprint returns a stable, secret-free identifier for a finding.
//
// It hashes the detector type, the slash-normalized location path, and the
// raw secret. Line numbers, commit hashes, verification state, and severity
// are deliberately excluded so that editing unrelated lines, re-running
// verification, or rewriting history does not invalidate a baseline entry.
// The same secret in a different file gets a different fingerprint, so a
// baselined fixture cannot hide a copy that leaks elsewhere. The output is
// a 32-hex-digit (128-bit) prefix of SHA-256; the secret is not recoverable
// from it beyond brute force over the secret space.
func Fingerprint(f Finding) string {
	h := sha256.New()
	h.Write([]byte(fingerprintVersion))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(f.Detector.String())))
	h.Write([]byte{0})
	h.Write([]byte(FingerprintPath(f)))
	h.Write([]byte{0})
	h.Write(f.Result.Raw)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// FingerprintPath returns the location path folded into Fingerprint:
// slash-separated, cleaned, and relative to the working directory when it
// is an absolute path beneath it.
func FingerprintPath(f Finding) string {
	return normalizeFingerprintPath(findingPath(f), fingerprintWorkdir())
}

// fingerprintWorkdir is resolved per call rather than cached so a process
// that changes directory (tests, embedders) never mixes two roots.
func fingerprintWorkdir() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(wd); err == nil {
		wd = r
	}
	return wd
}

func normalizeFingerprintPath(p, wd string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) && wd != "" {
		if rel, ok := relUnder(wd, p); ok {
			p = rel
		} else if r, err := filepath.EvalSymlinks(p); err == nil {
			if rel, ok := relUnder(wd, r); ok {
				p = rel
			}
		}
	}
	p = filepath.ToSlash(filepath.Clean(p))
	return strings.TrimPrefix(p, "./")
}

func relUnder(base, p string) (string, bool) {
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}
