//go:build opf_native

package opfnative

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
)

// modelRevision pins the HuggingFace commit the GGUF is fetched from, so a
// silent upstream reweight surfaces as a checksum mismatch (fatal) rather
// than a new model. Resolved from the LocalAI-io/privacy-filter-GGUF repo.
const modelRevision = "935d86882f4b5dc6e0eef05aae48ae5ba0a82a7a"

// DefaultVariant is the weight variant used when --pii-model is unset.
const DefaultVariant = "q8"

type modelVariant struct {
	file   string
	sha256 string
}

// modelVariants pins each downloadable weight file to its sha256. sha256 is
// the integrity gate; a downloaded file failing it is fatal (a DLP tool
// must not run inference on tampered model bytes).
var modelVariants = map[string]modelVariant{
	"q8": {
		file:   "privacy-filter-q8.gguf",
		sha256: "80efc1803eda7c095a79741d2008c07e2e0a57b01bac8825fbeb448fd097998c",
	},
	"f16": {
		file:   "privacy-filter-f16.gguf",
		sha256: "eb71312b6b9370d0fe582e576b840567bb06603c4de241c6d899205d1b04dc81",
	},
}

func modelURL(v modelVariant) string {
	return "https://huggingface.co/LocalAI-io/privacy-filter-GGUF/resolve/" + modelRevision + "/" + v.file
}

// ResolveModelPath returns a local GGUF path for the native engine.
//
// An explicit path (--pii-model-path) is trusted and returned as-is (it
// bypasses both download and checksum, per ADR-0005 §D). Otherwise the
// named variant is resolved to os.UserCacheDir()/pleno-dlp/models and
// downloaded on a cold cache. Download is atomic (.tmp -> verify -> rename),
// checksum-gated, and flock-guarded so concurrent runs don't double-fetch
// the multi-GB weights.
func ResolveModelPath(ctx context.Context, variant, explicitPath string, progress io.Writer) (string, error) {
	if explicitPath != "" {
		if _, err := os.Stat(explicitPath); err != nil {
			return "", fmt.Errorf("opfnative: --pii-model-path %q: %w", explicitPath, err)
		}
		return explicitPath, nil
	}
	if variant == "" {
		variant = DefaultVariant
	}
	mv, ok := modelVariants[variant]
	if !ok {
		return "", fmt.Errorf("%w: %q (valid: q8, f16)", ErrUnknownVariant, variant)
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("opfnative: locate cache dir: %w", err)
	}
	dir := filepath.Join(cacheDir, "pleno-dlp", "models")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("opfnative: create model cache dir: %w", err)
	}
	// The filename embeds the sha256 prefix, so a cached file's presence is
	// sufficient — no 1.5 GB re-hash per scan startup. Integrity is enforced
	// at download time on the bytes that land.
	dest := filepath.Join(dir, fmt.Sprintf("privacy-filter-%s-%s.gguf", variant, mv.sha256[:8]))
	if _, err := os.Stat(dest); err == nil {
		return dest, nil
	}
	if err := downloadVerified(ctx, modelURL(mv), dest, mv.sha256, progress); err != nil {
		return "", err
	}
	return dest, nil
}

func downloadVerified(ctx context.Context, url, dest, want string, progress io.Writer) error {
	lf, err := os.OpenFile(dest+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("opfnative: open model lock: %w", err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("opfnative: lock model cache: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }()

	// Another process may have completed the download while we blocked on
	// the lock.
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	if progress != nil {
		fmt.Fprintf(progress, "pii-engine: downloading %s\n", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("opfnative: download model: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("opfnative: download %s: status %d", url, resp.StatusCode)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("opfnative: write model: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		_ = os.Remove(tmp)
		return fmt.Errorf("%w: %s: got %s want %s", ErrChecksum, filepath.Base(dest), got, want)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("opfnative: install model: %w", err)
	}
	return nil
}
