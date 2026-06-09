// GitLab connector. Single-file Lambda-handler shape: auth, fetch, emit.
//
// Surface: group or single-project default-branch blobs, plus optional merge
// request notes and discussion notes.
//
// Auth: PAT (`glpat-...`) sent as `PRIVATE-TOKEN: <token>`, OAuth /
// other tokens sent as `Authorization: Bearer <token>`. The header is
// chosen by token-prefix detection.
//
// Pagination: Link header `rel="next"` cursors (keyset preferred for
// group enumeration). Shares parseLinkHeader with the GitHub connector.

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	gitlabDefaultAPIBase      = "https://gitlab.com/api/v4"
	gitlabDefaultMaxBlobBytes = int64(5 * 1024 * 1024)
	gitlabRequestTimeout      = 60 * time.Second
)

func init() {
	Register("gitlab", Connector{
		SourceType:  sources.SourceGitLab,
		Scan:        scanGitLab,
		Verify:      verifyGitLab,
		Fingerprint: fingerprintGitLab,
	})
}

// scanGitLab is the Lambda handler. cfg keys:
//   - token       (required) PAT or OAuth token
//   - group       group path (mutually exclusive with project)
//   - project     namespace/name single-project scope
//   - api_base    override https://gitlab.com/api/v4
//   - max_blob_bytes per-blob size cap
//   - concurrency per-project blob fanout
//   - include_comments scan merge request notes and discussion notes
func scanGitLab(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return errors.New("gitlab: token is required (set --token or GITLAB_TOKEN)")
	}
	group, project := cfg["group"], cfg["project"]
	if group == "" && project == "" {
		return errors.New("gitlab: either group or project must be set")
	}
	if group != "" && project != "" {
		return errors.New("gitlab: group and project are mutually exclusive")
	}
	if project != "" {
		parts := strings.SplitN(project, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("gitlab: project must be in namespace/name form, got %q", project)
		}
	}
	apiBase := cfg.Get("api_base", gitlabDefaultAPIBase)
	if u, err := url.Parse(apiBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("gitlab: invalid api_base %q", apiBase)
	}
	maxBytes := gitlabDefaultMaxBlobBytes
	if v := cfg["max_blob_bytes"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}
	concurrency := 4
	if v := cfg["concurrency"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			concurrency = n
		}
	}

	cli := newGitLabClient(apiBase, token)
	projects, err := gitlabListProjects(ctx, cli, group, project)
	if err != nil {
		return err
	}
	previousState, err := loadGitLabIncrementalState(cfg[configKeyIncrementalPreviousState])
	if err != nil {
		return err
	}
	nextState := &gitlabIncrementalState{Version: 1, Projects: map[string]gitlabProjectIncrementalState{}}
	if previousState == nil {
		previousState = &gitlabIncrementalState{Version: 1, Projects: map[string]gitlabProjectIncrementalState{}}
	}
	for _, p := range projects {
		if err := ctx.Err(); err != nil {
			return err
		}
		projectKey := p.PathWithNS
		if projectKey == "" {
			projectKey = strconv.FormatInt(p.ID, 10)
		}
		prevProject, hasPrevProject := previousState.Projects[projectKey]
		nextProject, err := scanGitLabProjectIncremental(ctx, cli, p, group, prevProject, hasPrevProject, maxBytes, concurrency, emit)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
		if parseBool(cfg["include_comments"]) {
			if err := scanGitLabMergeRequestCommentsIncremental(ctx, cli, p, group, prevProject, hasPrevProject, &nextProject, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}
		nextState.Projects[projectKey] = nextProject
	}
	data, err := json.Marshal(nextState)
	if err != nil {
		return fmt.Errorf("gitlab: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	return nil
}

func verifyGitLab(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", gitlabDefaultAPIBase)
	cli := newGitLabClient(apiBase, secret)
	resp, err := cli.do(ctx, http.MethodGet, "/user", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("gitlab: verify unexpected status %s", resp.Status)
	}
}

func fingerprintGitLab(ctx context.Context, cfg Config) (string, error) {
	token := cfg["token"]
	if token == "" {
		return "", errors.New("gitlab: token is required (set --token or GITLAB_TOKEN)")
	}
	group, project := cfg["group"], cfg["project"]
	if group == "" && project == "" {
		return "", errors.New("gitlab: either group or project must be set")
	}
	if group != "" && project != "" {
		return "", errors.New("gitlab: group and project are mutually exclusive")
	}
	apiBase := cfg.Get("api_base", gitlabDefaultAPIBase)
	cli := newGitLabClient(apiBase, token)
	projects, err := gitlabListProjects(ctx, cli, group, project)
	if err != nil {
		return "", err
	}
	sort.Slice(projects, func(i, j int) bool {
		return projects[i].PathWithNS < projects[j].PathWithNS
	})

	h := sha256.New()
	writeFingerprint(h, "gitlab-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, group)
	writeFingerprint(h, project)
	writeFingerprint(h, cfg.Get("include_comments", "false"))
	for _, p := range projects {
		if err := fingerprintGitLabProject(ctx, h, cli, p, parseBool(cfg["include_comments"])); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fingerprintGitLabProject(ctx context.Context, h hash.Hash, cli *gitlabClient, proj gitlabProjectRef, includeComments bool) error {
	if proj.DefaultBranch == "" {
		path := fmt.Sprintf("/projects/%d", proj.ID)
		if _, err := cli.getJSON(ctx, path, &proj); err != nil {
			return fmt.Errorf("gitlab: resolve default branch for project %d: %w", proj.ID, err)
		}
	}
	writeFingerprint(h, strconv.FormatInt(proj.ID, 10))
	writeFingerprint(h, proj.PathWithNS)
	writeFingerprint(h, proj.DefaultBranch)
	if proj.DefaultBranch != "" {
		var entries []gitlabTreeEntry
		next := fmt.Sprintf("/projects/%d/repository/tree?recursive=true&per_page=100&ref=%s",
			proj.ID, url.QueryEscape(proj.DefaultBranch))
		for next != "" {
			var page []gitlabTreeEntry
			resp, err := cli.getJSON(ctx, next, &page)
			if err != nil {
				return fmt.Errorf("gitlab: tree project %d@%s: %w", proj.ID, proj.DefaultBranch, err)
			}
			entries = append(entries, page...)
			next = parseLinkHeader(resp.Header.Get("Link"))
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		for _, entry := range entries {
			if entry.Type != "blob" {
				continue
			}
			writeFingerprint(h, "blob")
			writeFingerprint(h, entry.Path)
			writeFingerprint(h, entry.ID)
		}
	}
	if includeComments {
		return fingerprintGitLabMergeRequestComments(ctx, h, cli, proj)
	}
	return nil
}

func fingerprintGitLabMergeRequestComments(ctx context.Context, h hash.Hash, cli *gitlabClient, proj gitlabProjectRef) error {
	next := fmt.Sprintf("/projects/%d/merge_requests?state=all&per_page=100", proj.ID)
	for next != "" {
		var page []gitlabMergeRequestRef
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("gitlab: list merge requests for project %d: %w", proj.ID, err)
		}
		for _, mr := range page {
			if err := fingerprintGitLabMergeRequestNotes(ctx, h, cli, proj, mr); err != nil {
				return err
			}
			if err := fingerprintGitLabMergeRequestDiscussions(ctx, h, cli, proj, mr); err != nil {
				return err
			}
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func fingerprintGitLabMergeRequestNotes(ctx context.Context, h hash.Hash, cli *gitlabClient, proj gitlabProjectRef, mr gitlabMergeRequestRef) error {
	next := fmt.Sprintf("/projects/%d/merge_requests/%d/notes?per_page=100", proj.ID, mr.IID)
	for next != "" {
		var page []gitlabNote
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("gitlab: list merge request notes for project %d MR !%d: %w", proj.ID, mr.IID, err)
		}
		for _, note := range page {
			writeFingerprint(h, "mr-note")
			writeFingerprint(h, strconv.FormatInt(mr.IID, 10))
			writeFingerprint(h, strconv.FormatInt(note.ID, 10))
			writeFingerprint(h, note.UpdatedAt)
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func fingerprintGitLabMergeRequestDiscussions(ctx context.Context, h hash.Hash, cli *gitlabClient, proj gitlabProjectRef, mr gitlabMergeRequestRef) error {
	next := fmt.Sprintf("/projects/%d/merge_requests/%d/discussions?per_page=100", proj.ID, mr.IID)
	for next != "" {
		var page []gitlabDiscussion
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("gitlab: list merge request discussions for project %d MR !%d: %w", proj.ID, mr.IID, err)
		}
		for _, discussion := range page {
			for _, note := range discussion.Notes {
				writeFingerprint(h, "mr-discussion")
				writeFingerprint(h, strconv.FormatInt(mr.IID, 10))
				writeFingerprint(h, discussion.ID)
				writeFingerprint(h, strconv.FormatInt(note.ID, 10))
				writeFingerprint(h, note.UpdatedAt)
			}
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

// --- internal types ---

type gitlabProjectRef struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	PathWithNS    string `json:"path_with_namespace"`
	DefaultBranch string `json:"default_branch"`
}

type gitlabTreeEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type gitlabMergeRequestRef struct {
	IID   int64  `json:"iid"`
	Title string `json:"title"`
}

type gitlabNote struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Body      string `json:"body"`
	UpdatedAt string `json:"updated_at"`
}

type gitlabDiscussion struct {
	ID    string       `json:"id"`
	Notes []gitlabNote `json:"notes"`
}

type gitlabIncrementalState struct {
	Version  int                                      `json:"version"`
	Projects map[string]gitlabProjectIncrementalState `json:"projects"`
}

type gitlabProjectIncrementalState struct {
	DefaultBranch string                                `json:"default_branch,omitempty"`
	Blobs         map[string]gitlabBlobIncrementalState `json:"blobs,omitempty"`
	MRNotes       map[string]gitlabNoteIncrementalState `json:"mr_notes,omitempty"`
}

type gitlabBlobIncrementalState struct {
	ID   string `json:"id"`
	Size int64  `json:"size,omitempty"`
}

type gitlabNoteIncrementalState struct {
	UpdatedAt string `json:"updated_at,omitempty"`
}

func loadGitLabIncrementalState(raw string) (*gitlabIncrementalState, error) {
	if raw == "" {
		return nil, nil
	}
	var state gitlabIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("gitlab: parse incremental source state: %w", err)
	}
	if state.Projects == nil {
		state.Projects = map[string]gitlabProjectIncrementalState{}
	}
	return &state, nil
}

func gitlabListProjects(ctx context.Context, cli *gitlabClient, group, project string) ([]gitlabProjectRef, error) {
	if project != "" {
		encoded := url.PathEscape(project)
		path := fmt.Sprintf("/projects/%s", encoded)
		var p gitlabProjectRef
		if _, err := cli.getJSON(ctx, path, &p); err != nil {
			return nil, fmt.Errorf("gitlab: get project %s: %w", project, err)
		}
		return []gitlabProjectRef{p}, nil
	}
	var projects []gitlabProjectRef
	next := fmt.Sprintf("/groups/%s/projects?include_subgroups=true&per_page=100&pagination=keyset&order_by=id",
		url.PathEscape(group))
	for next != "" {
		var page []gitlabProjectRef
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return nil, fmt.Errorf("gitlab: list group %s projects: %w", group, err)
		}
		projects = append(projects, page...)
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return projects, nil
}

func emitGitLabNote(proj gitlabProjectRef, group string, mr gitlabMergeRequestRef, part string, note gitlabNote, emit Emit) error {
	body := strings.TrimSpace(note.Body)
	if body == "" {
		return nil
	}
	return emit([]byte(body), sources.Metadata{
		GitLab: &sources.GitLabMeta{
			ProjectID: proj.ID,
			Path:      fmt.Sprintf("%s:!%d:%d", part, mr.IID, note.ID),
			Group:     group,
			Project:   proj.PathWithNS,
		},
	})
}

func scanGitLabMergeRequestCommentsIncremental(ctx context.Context, cli *gitlabClient, proj gitlabProjectRef, group string, prev gitlabProjectIncrementalState, hasPrev bool, nextProject *gitlabProjectIncrementalState, emit Emit) error {
	if nextProject.MRNotes == nil {
		nextProject.MRNotes = map[string]gitlabNoteIncrementalState{}
	}
	next := fmt.Sprintf("/projects/%d/merge_requests?state=all&per_page=100", proj.ID)
	for next != "" {
		var page []gitlabMergeRequestRef
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("gitlab: list merge requests for project %d: %w", proj.ID, err)
		}
		for _, mr := range page {
			if err := scanGitLabMergeRequestNotesIncremental(ctx, cli, proj, group, mr, prev, hasPrev, nextProject, emit); err != nil {
				return err
			}
			if err := scanGitLabMergeRequestDiscussionsIncremental(ctx, cli, proj, group, mr, prev, hasPrev, nextProject, emit); err != nil {
				return err
			}
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func scanGitLabMergeRequestNotesIncremental(ctx context.Context, cli *gitlabClient, proj gitlabProjectRef, group string, mr gitlabMergeRequestRef, prev gitlabProjectIncrementalState, hasPrev bool, nextProject *gitlabProjectIncrementalState, emit Emit) error {
	next := fmt.Sprintf("/projects/%d/merge_requests/%d/notes?per_page=100", proj.ID, mr.IID)
	for next != "" {
		var page []gitlabNote
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("gitlab: list merge request notes for project %d MR !%d: %w", proj.ID, mr.IID, err)
		}
		for _, note := range page {
			key := gitlabNoteKey("merge-request-note", mr.IID, "", note.ID)
			state := gitlabNoteIncrementalState{UpdatedAt: note.UpdatedAt}
			nextProject.MRNotes[key] = state
			if hasPrev && prev.MRNotes != nil && prev.MRNotes[key] == state {
				continue
			}
			if err := emitGitLabNote(proj, group, mr, "merge-request-note", note, emit); err != nil {
				return err
			}
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func scanGitLabMergeRequestDiscussionsIncremental(ctx context.Context, cli *gitlabClient, proj gitlabProjectRef, group string, mr gitlabMergeRequestRef, prev gitlabProjectIncrementalState, hasPrev bool, nextProject *gitlabProjectIncrementalState, emit Emit) error {
	next := fmt.Sprintf("/projects/%d/merge_requests/%d/discussions?per_page=100", proj.ID, mr.IID)
	for next != "" {
		var page []gitlabDiscussion
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("gitlab: list merge request discussions for project %d MR !%d: %w", proj.ID, mr.IID, err)
		}
		for _, discussion := range page {
			for _, note := range discussion.Notes {
				part := "merge-request-discussion:" + discussion.ID
				key := gitlabNoteKey("merge-request-discussion", mr.IID, discussion.ID, note.ID)
				state := gitlabNoteIncrementalState{UpdatedAt: note.UpdatedAt}
				nextProject.MRNotes[key] = state
				if hasPrev && prev.MRNotes != nil && prev.MRNotes[key] == state {
					continue
				}
				if err := emitGitLabNote(proj, group, mr, part, note, emit); err != nil {
					return err
				}
			}
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func gitlabNoteKey(kind string, mrIID int64, discussionID string, noteID int64) string {
	if discussionID != "" {
		return fmt.Sprintf("%s:!%d:%s:%d", kind, mrIID, discussionID, noteID)
	}
	return fmt.Sprintf("%s:!%d:%d", kind, mrIID, noteID)
}

func scanGitLabProjectIncremental(ctx context.Context, cli *gitlabClient, proj gitlabProjectRef, group string, prev gitlabProjectIncrementalState, hasPrev bool, maxBytes int64, concurrency int, emit Emit) (gitlabProjectIncrementalState, error) {
	if proj.DefaultBranch == "" {
		path := fmt.Sprintf("/projects/%d", proj.ID)
		if _, err := cli.getJSON(ctx, path, &proj); err != nil {
			return gitlabProjectIncrementalState{}, fmt.Errorf("gitlab: resolve default branch for project %d: %w", proj.ID, err)
		}
	}
	nextProject := gitlabProjectIncrementalState{
		DefaultBranch: proj.DefaultBranch,
		Blobs:         map[string]gitlabBlobIncrementalState{},
	}
	if proj.DefaultBranch == "" {
		return nextProject, nil
	}
	var entries []gitlabTreeEntry
	next := fmt.Sprintf("/projects/%d/repository/tree?recursive=true&per_page=100&ref=%s",
		proj.ID, url.QueryEscape(proj.DefaultBranch))
	for next != "" {
		var page []gitlabTreeEntry
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return gitlabProjectIncrementalState{}, fmt.Errorf("gitlab: tree project %d@%s: %w", proj.ID, proj.DefaultBranch, err)
		}
		entries = append(entries, page...)
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, concurrency)
	for _, entry := range entries {
		entry := entry
		if entry.Type != "blob" {
			continue
		}
		state := gitlabBlobIncrementalState{ID: entry.ID}
		nextProject.Blobs[entry.Path] = state
		if hasPrev && prev.Blobs != nil && prev.Blobs[entry.Path] == state {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-gctx.Done():
			return gitlabProjectIncrementalState{}, gctx.Err()
		}
		g.Go(func() error {
			defer func() { <-sem }()
			return emitGitLabBlob(gctx, cli, proj, group, entry, maxBytes, emit)
		})
	}
	if err := g.Wait(); err != nil {
		return gitlabProjectIncrementalState{}, err
	}
	return nextProject, nil
}

func emitGitLabBlob(ctx context.Context, cli *gitlabClient, proj gitlabProjectRef, group string, entry gitlabTreeEntry, maxBytes int64, emit Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := fmt.Sprintf("/projects/%d/repository/files/%s/raw?ref=%s",
		proj.ID, url.PathEscape(entry.Path), url.QueryEscape(proj.DefaultBranch))
	resp, err := cli.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil
	}
	if int64(len(data)) > maxBytes {
		return nil
	}
	return emit(data, sources.Metadata{
		GitLab: &sources.GitLabMeta{
			ProjectID: proj.ID,
			Path:      entry.Path,
			Sha:       entry.ID,
			Branch:    proj.DefaultBranch,
			Group:     group,
			Project:   proj.PathWithNS,
		},
	})
}

// --- rate-limit-aware HTTP client ---

type gitlabClient struct {
	base       string
	token      string
	tokenIsPAT bool
	http       *http.Client

	mu          sync.Mutex
	nextAllowed time.Time

	testSleep func(time.Duration)
}

func newGitLabClient(base, token string) *gitlabClient {
	if base == "" {
		base = gitlabDefaultAPIBase
	}
	return &gitlabClient{
		base:       base,
		token:      token,
		tokenIsPAT: strings.HasPrefix(token, "glpat-"),
		http:       &http.Client{Timeout: gitlabRequestTimeout},
	}
}

func (c *gitlabClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.waitForBucket(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
		if err != nil {
			return nil, err
		}
		if c.token != "" {
			if c.tokenIsPAT {
				req.Header.Set("PRIVATE-TOKEN", c.token)
			} else {
				req.Header.Set("Authorization", "Bearer "+c.token)
			}
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
			continue
		}
		c.observeRateLimit(resp)
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := gitlabBackoff(resp, attempt)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if c.testSleep != nil {
				c.testSleep(wait)
				continue
			}
			if wait <= 0 {
				wait = time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("gitlab: exhausted retries against rate limit")
	}
	return nil, lastErr
}

func (c *gitlabClient) getJSON(ctx context.Context, path string, out any) (*http.Response, error) {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp, fmt.Errorf("gitlab: GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("gitlab: decode %s: %w", path, err)
		}
	}
	return resp, nil
}

func (c *gitlabClient) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.base, "/") + p
}

func (c *gitlabClient) waitForBucket(ctx context.Context) error {
	c.mu.Lock()
	until := c.nextAllowed
	c.mu.Unlock()
	if until.IsZero() {
		return nil
	}
	delay := time.Until(until)
	if delay <= 0 {
		return nil
	}
	if c.testSleep != nil {
		c.testSleep(delay)
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

func (c *gitlabClient) observeRateLimit(resp *http.Response) {
	rem := resp.Header.Get("RateLimit-Remaining")
	reset := resp.Header.Get("RateLimit-Reset")
	if rem == "" || rem != "0" || reset == "" {
		return
	}
	ts, err := strconv.ParseInt(reset, 10, 64)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.nextAllowed = time.Unix(ts, 0)
	c.mu.Unlock()
}

func gitlabBackoff(resp *http.Response, attempt int) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	if v := resp.Header.Get("RateLimit-Reset"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(ts, 0)); d > 0 {
				return d
			}
		}
	}
	d := time.Duration(1<<attempt) * time.Second
	if d > time.Minute {
		d = time.Minute
	}
	return d
}
