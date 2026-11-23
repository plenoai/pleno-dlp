// Shared remote Git history walker.
//
// Several connectors (Azure DevOps, Gitea/Forgejo, GitLab, Bitbucket, and the
// generic remote --git-url source) need the same thing: clone a remote
// repository into a throwaway bare directory, walk its full history with the
// core git source, and re-label each chunk with forge provenance. Before this
// helper every connector that wanted history re-implemented the clone +
// bridge loop (see huggingface.go); new connectors must use this one so the
// transport rules and incremental checkpoints stay identical.
//
// Transport: credentials are only sent to HTTPS (or loopback HTTP) clone
// URLs. Unauthenticated clones accept any URL go-git understands, including
// local paths, which is what the --git-url source and tests rely on.
//
// Incremental: the git source's own per-ref incremental state is persisted
// per repository key, so a re-scan only walks commits added since the last
// checkpoint.
package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/plenoai/pleno-dlp/pkg/sources"
	gitsource "github.com/plenoai/pleno-dlp/pkg/sources/git"
)

// remoteGitRepo identifies one repository to clone and walk.
type remoteGitRepo struct {
	// Key is the stable incremental-state key and the ForgeMeta.Repository
	// value (e.g. "org/project/repo").
	Key      string
	CloneURL string
	Username string
	Password string
}

// scanRemoteGitRepo clones repo, walks its history from previous state, and
// returns the next git-source state.
func scanRemoteGitRepo(ctx context.Context, provider string, repo remoteGitRepo, previous json.RawMessage, emit Emit) (json.RawMessage, error) {
	if repo.CloneURL == "" {
		return nil, fmt.Errorf("%s: clone URL is required for %s", provider, repo.Key)
	}
	dir, cleanup, err := gitsource.CloneRemote(ctx, repo.CloneURL, gitsource.RemoteAuth{Username: repo.Username, Password: repo.Password})
	if errors.Is(err, gitsource.ErrRemoteEmpty) {
		return previous, nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s: %s: %w", provider, repo.Key, err)
	}
	defer cleanup()

	raw, err := json.Marshal(gitsource.Config{Repo: dir, AllBranches: true})
	if err != nil {
		return nil, err
	}
	src := &gitsource.Source{}
	if err := src.Init(ctx, provider, 0, 0, false, raw, 1); err != nil {
		return nil, fmt.Errorf("%s: init git walk for %s: %w", provider, repo.Key, err)
	}
	if err := src.SetIncrementalState(previous); err != nil {
		// A corrupt per-repo checkpoint must not wedge the scan: fall back to
		// a full walk, which is the safe (superset) behaviour.
		_ = src.SetIncrementalState(nil)
	}

	ch := make(chan *sources.Chunk, 64)
	walkCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	walkErr := make(chan error, 1)
	go func() {
		walkErr <- src.Chunks(walkCtx, ch)
		close(ch)
	}()
	var emitErr error
	for c := range ch {
		if emitErr != nil {
			continue
		}
		gm := c.SourceMetadata.Git
		if gm == nil {
			continue
		}
		meta := sources.Metadata{Forge: &sources.ForgeMeta{
			Provider:   provider,
			Repository: repo.Key,
			Commit:     gm.Commit,
			File:       gm.File,
			Line:       gm.Line,
		}}
		if err := emit(c.Data, meta); err != nil {
			emitErr = err
			cancel()
		}
	}
	if err := <-walkErr; err != nil && emitErr == nil {
		return nil, fmt.Errorf("%s: walk %s: %w", provider, repo.Key, err)
	}
	if emitErr != nil {
		return nil, emitErr
	}
	return src.IncrementalState(), nil
}
