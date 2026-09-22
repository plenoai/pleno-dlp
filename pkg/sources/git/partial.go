// Partial-clone walk support.
//
// A repository cloned with `--filter=blob:limit=<n>` is a promisor clone:
// commits and trees arrive complete while blobs above the limit stay on the
// remote and would normally need an authenticated demand-fetch. The scanner
// never emits blobs above its artifact ceiling anyway, so the omitted set is
// exactly the set the walk could never read. Detection is config-based
// (remote.*.promisor, remote.*.partialclonefilter, extensions.partialclone)
// so it works without a git binary and without trusting caller flags; blob
// presence is then checked per changed entry and absent promisor blobs are
// skipped intentionally instead of failing the walk or fetching lazily.
package git

import (
	"errors"
	"fmt"
	"os"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage"
)

// CloneBlobLimitBytes returns the `--filter=blob:limit=<n>` value a clone may
// apply with zero coverage loss: every blob the server omits is one the walk
// could never emit. Text content is capped at maxBlobSize; artifact scans
// raise the ceiling only when binary or archive emission is enabled, so an
// emitted artifact can never be an omitted promisor blob either.
func CloneBlobLimitBytes(c Config) int64 {
	limit := maxBlobSize
	if c.IncludeGitBinaries || c.IncludeGitArchives {
		if c.GitArtifactMaxBytes > limit {
			limit = c.GitArtifactMaxBytes
		}
	}
	return limit
}

// isPartialCloneRepo reports whether the repository's own config marks it as
// a promisor clone. It reads only local config — no remote contact.
func isPartialCloneRepo(repo *gogit.Repository) bool {
	cfg, err := repo.Config()
	if err != nil || cfg == nil || cfg.Raw == nil {
		return false
	}
	if cfg.Raw.HasSection("remote") {
		for _, sub := range cfg.Raw.Section("remote").Subsections {
			if sub.Options.Has("partialclonefilter") || sub.Options.Has("promisor") {
				return true
			}
		}
	}
	if cfg.Raw.HasSection("extensions") {
		return cfg.Raw.Section("extensions").Options.Has("partialclone")
	}
	return false
}

// blobMissing reports whether a tree entry refers to a blob absent from the
// local object store — an omitted promisor object under a blob filter. The
// empty side of an add/delete, directories, and gitlinks are not blobs and
// never count. Storage errors other than not-found report false so genuine
// corruption still surfaces through the caller's normal error path instead of
// being misclassified as an intentional skip.
func blobMissing(st storage.Storer, e object.TreeEntry) bool {
	if e.Hash == plumbing.ZeroHash || !e.Mode.IsFile() {
		return false
	}
	return errors.Is(st.HasEncodedObject(e.Hash), plumbing.ErrObjectNotFound)
}

// fileForPresentBlob rebuilds the File for a change entry whose blob is known
// to exist locally. It is used to keep scanning the present side of a change
// when the other side is an omitted promisor blob.
func fileForPresentBlob(st storage.Storer, name string, e object.TreeEntry) *object.File {
	blob, err := object.GetBlob(st, e.Hash)
	if err != nil {
		return nil
	}
	return object.NewFile(name, e.Mode, blob)
}

func (s *Source) logPartialSkipSummary() {
	if s.partialSkips == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "git: partial clone: %d omitted promisor blob(s) skipped intentionally\n", s.partialSkips)
}
