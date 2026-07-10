package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type githubGistRef struct {
	ID         string `json:"id"`
	GitPullURL string `json:"git_pull_url"`
	HTMLURL    string `json:"html_url"`
	Public     bool   `json:"public"`
	Owner      struct {
		Login string `json:"login"`
	} `json:"owner"`
}
type githubGistComment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	UpdatedAt string `json:"updated_at"`
	HTMLURL   string `json:"html_url"`
}

func deriveGistCloneURL(apiBase, id string) (string, error) {
	if id == "" {
		return "", errors.New("github: empty gist id")
	}
	if strings.TrimRight(apiBase, "/") == githubDefaultAPIBase {
		return "https://gist.github.com/" + url.PathEscape(id) + ".git", nil
	}
	u, err := url.Parse(apiBase)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("github: invalid api_base %q", apiBase)
	}
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v3") + "/gist/" + url.PathEscape(id) + ".git"
	return u.String(), nil
}

var gistIDPattern = regexp.MustCompile(`^[A-Fa-f0-9]+$`)

func gistID(ctx context.Context, raw, apiBase string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("github: empty gist")
	}
	if !strings.Contains(raw, "://") {
		id := strings.TrimSuffix(raw, ".git")
		if !gistIDPattern.MatchString(id) {
			return "", fmt.Errorf("github: invalid gist id %q", id)
		}
		return id, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") || strings.Contains(strings.ToLower(u.EscapedPath()), "%2e") {
		return "", fmt.Errorf("github: invalid gist URL %q", raw)
	}
	allowed := u.Hostname() == "gist.github.com"
	if base, err := url.Parse(apiBase); err == nil && u.Hostname() == base.Hostname() {
		allowed = true
	}
	if !allowed {
		return "", fmt.Errorf("github: untrusted gist URL origin %q", u.Host)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("github: invalid gist URL %q", raw)
	}
	id := strings.TrimSuffix(parts[len(parts)-1], ".git")
	if !gistIDPattern.MatchString(id) {
		return "", fmt.Errorf("github: invalid gist id %q", id)
	}
	return id, nil
}

func canonicalGistWebURL(apiBase, id string) string {
	if strings.TrimRight(apiBase, "/") == githubDefaultAPIBase {
		return "https://gist.github.com/" + url.PathEscape(id)
	}
	u, _ := url.Parse(apiBase)
	return "https://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v3") + "/gist/" + url.PathEscape(id)
}
func validateGistCloneURL(apiBase, id, raw string) (string, error) {
	expected, err := deriveGistCloneURL(apiBase, id)
	if err != nil {
		return "", err
	}
	u, e := url.Parse(raw)
	x, _ := url.Parse(expected)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Host != x.Host || u.EscapedPath() != x.EscapedPath() {
		return "", fmt.Errorf("github: untrusted gist clone URL for %s", id)
	}
	return raw, nil
}

func scanGitHubGists(ctx context.Context, cfg Config, auth githubTokenProvider, apiBase string, emit Emit) error {
	cli := newGitHubClient(apiBase, auth)
	byID := map[string]githubGistRef{}
	var failures []engine.ScanFailure
	var skippedEmpty atomic.Int64
	for _, raw := range splitNonEmptyLines(cfg["gist_urls"]) {
		id, err := gistID(ctx, raw, apiBase)
		if err != nil {
			return err
		}
		var gist githubGistRef
		if _, err := cli.getJSON(ctx, "/gists/"+url.PathEscape(id), &gist); err != nil {
			failures = append(failures, engine.ScanFailure{Kind: engine.FailureSource, Source: "gist-history:" + id, Err: fmt.Errorf("github: get gist %s: %w", id, err)})
			continue
		}
		if gist.ID == "" {
			gist.ID = id
		}
		byID[gist.ID] = gist
	}
	if parseBool(cfg["include_authenticated_gists"]) {
		next := "/gists?per_page=100"
		for next != "" {
			var page []githubGistRef
			resp, err := cli.getJSON(ctx, next, &page)
			if err != nil {
				failures = append(failures, engine.ScanFailure{Kind: engine.FailureSource, Source: "gist-enumeration:authenticated", Err: fmt.Errorf("github: list authenticated gists: %w", err)})
				break
			}
			for _, g := range page {
				byID[g.ID] = g
			}
			next = parseLinkHeader(resp.Header.Get("Link"))
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rawState := cfg[configKeyIncrementalNextState]
	if rawState == "" {
		rawState = cfg[configKeyIncrementalPreviousState]
	}
	state, err := loadGitHubIncrementalState(rawState)
	if err != nil {
		return err
	}
	if state == nil {
		state = &githubIncrementalState{Version: 2, Surfaces: map[string]map[string]githubRepoIncrementalState{}}
	}
	if state.Surfaces == nil {
		state.Surfaces = map[string]map[string]githubRepoIncrementalState{}
	}
	for _, surface := range []string{"gist-history", "gist-comments"} {
		if state.Surfaces[surface] == nil {
			state.Surfaces[surface] = map[string]githubRepoIncrementalState{}
		}
	}
	units := make([]githubSourceUnit, 0, len(ids)*2)
	for _, id := range ids {
		units = append(units, githubSourceUnit{Surface: "gist-history", ID: id})
		if parseBool(cfg["include_gist_comments"]) {
			units = append(units, githubSourceUnit{Surface: "gist-comments", ID: id})
		}
	}
	type outcome struct {
		State githubRepoIncrementalState
		Valid bool
	}
	unitOrder := make(map[string]int, len(units))
	for i, u := range units {
		unitOrder[u.Key()] = i
	}
	orderedEmit := newGitHubOrderedEmitter(ctx, len(units), emit)
	produce := func(ctx context.Context, u githubSourceUnit) githubUnitResult[outcome] {
		order := unitOrder[u.Key()]
		unitEmit := orderedEmit.Emit(order)
		g := byID[u.ID]
		prev := state.Surfaces[u.Surface][u.ID]
		if u.Surface == "gist-comments" {
			next := prev
			next.IssueComments = make(map[string]githubCommentIncrementalState, len(prev.IssueComments))
			for id, s := range prev.IssueComments {
				next.IssueComments[id] = s
			}
			nextPath := "/gists/" + url.PathEscape(u.ID) + "/comments?per_page=100"
			for nextPath != "" {
				var page []githubGistComment
				resp, err := cli.getJSON(ctx, nextPath, &page)
				if err != nil {
					return githubUnitResult[outcome]{State: outcome{prev, true}, Err: err}
				}
				for _, c := range page {
					id := fmt.Sprint(c.ID)
					if old, ok := prev.IssueComments[id]; ok && old.UpdatedAt == c.UpdatedAt {
						continue
					}
					next.IssueComments[id] = githubCommentIncrementalState{UpdatedAt: c.UpdatedAt}
					body := strings.TrimSpace(c.Body)
					if body == "" {
						skippedEmpty.Add(1)
						continue
					}
					link := canonicalGistWebURL(apiBase, u.ID) + "#gistcomment-" + id
					if err := unitEmit([]byte(body), sources.Metadata{GitHub: &sources.GitHubMeta{Repository: "gist:" + u.ID, Owner: g.Owner.Login, Repo: u.ID, Link: link, File: "gist-comment:" + id, Path: "gist-comment:" + id, Entity: "gist_comment", Part: "body", Visibility: map[bool]string{true: "public", false: "secret"}[g.Public]}}); err != nil {
						return githubUnitResult[outcome]{State: outcome{prev, true}, Err: err}
					}
				}
				nextPath = parseLinkHeader(resp.Header.Get("Link"))
			}
			return githubUnitResult[outcome]{State: outcome{next, true}}
		}
		clone := g.GitPullURL
		if template := cfg["gist_clone_url_template"]; template != "" {
			clone = strings.ReplaceAll(template, "{id}", u.ID)
			if err := validateGitHubCloneTarget(apiBase, clone); err != nil {
				return githubUnitResult[outcome]{State: outcome{prev, prev.Mode == githubScanModeHistory}, Err: err}
			}
		} else if clone == "" {
			var deriveErr error
			clone, deriveErr = deriveGistCloneURL(apiBase, u.ID)
			if deriveErr != nil {
				return githubUnitResult[outcome]{State: outcome{prev, prev.Mode == githubScanModeHistory}, Err: deriveErr}
			}
		} else {
			validated, validateErr := validateGistCloneURL(apiBase, u.ID, clone)
			if validateErr != nil {
				return githubUnitResult[outcome]{State: outcome{prev, prev.Mode == githubScanModeHistory}, Err: validateErr}
			}
			clone = validated
		}
		repo := githubRepoRef{Name: u.ID, Visibility: map[bool]string{true: "public", false: "secret"}[g.Public]}
		repo.Owner.Login = g.Owner.Login
		if repo.Owner.Login == "" {
			repo.Owner.Login = "gist"
		}
		wrapped := func(data []byte, meta sources.Metadata) error {
			if meta.GitHub != nil {
				meta.GitHub.Repository = "gist:" + u.ID
				meta.GitHub.Entity = "gist"
				meta.GitHub.Part = "content"
				meta.GitHub.Link = canonicalGistWebURL(apiBase, u.ID)
			}
			return unitEmit(data, meta)
		}
		next, e := scanGitHubGitHistory(ctx, cfg, auth, githubHostFromAPIBase(apiBase), clone, repo, prev, false, wrapped)
		return githubUnitResult[outcome]{State: outcome{next, e == nil || prev.Mode == githubScanModeHistory}, Err: e}
	}
	concurrency, err := githubRepoConcurrency(cfg)
	if err != nil {
		return err
	}
	_, err = runGitHubSourceUnits(ctx, units, concurrency, produce, func(_ int, r githubUnitResult[outcome]) error {
		if err := orderedEmit.Close(unitOrder[r.Unit.Key()]); err != nil {
			return err
		}
		if r.State.Valid {
			state.Surfaces[r.Unit.Surface][r.Unit.ID] = r.State.State
		}
		if r.Err != nil {
			failures = append(failures, engine.ScanFailure{Kind: engine.FailureSource, Source: r.Unit.Key(), Err: r.Err})
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := orderedEmit.Wait(); err != nil {
		return err
	}
	if n := skippedEmpty.Load(); n > 0 {
		fmt.Fprintf(os.Stderr, "github: gist comments skipped-empty=%d\n", n)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	cfg[configKeyIncrementalNextState] = string(data)
	var flushErr error
	if flush := IncrementalFlushFromContext(ctx); flush != nil {
		flushErr = flush(data)
	}
	if len(failures) > 0 {
		return errors.Join(&engine.DegradedError{Total: len(failures), Counts: map[engine.FailureKind]int{engine.FailureSource: len(failures)}, Failures: failures}, flushErr)
	}
	return flushErr
}
