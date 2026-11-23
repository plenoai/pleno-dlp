package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// githubEventsMaxPages mirrors GitHub's public-events retention: the API
// serves at most 300 events (10 pages of 30, or 3 of 100).
const githubEventsMaxPages = 10

type githubEvent struct {
	ID        string                `json:"id"`
	Type      string                `json:"type"`
	CreatedAt string                `json:"created_at"`
	Repo      struct{ Name string } `json:"repo"`
	Payload   json.RawMessage       `json:"payload"`
}

// scanGitHubUserEvents emits the text carried by each user's public events
// (push commit messages, issue/PR/comment/review bodies, release notes,
// wiki page titles). Each event is one chunk. A failing user feed is a
// coverage gap; other users continue.
func scanGitHubUserEvents(ctx context.Context, cli *githubClient, users []string, since time.Time, emit Emit) error {
	var failures []engine.ScanFailure
	for _, login := range users {
		if err := ctx.Err(); err != nil {
			return err
		}
		next := fmt.Sprintf("/users/%s/events/public?per_page=100", url.PathEscape(login))
		for page := 0; next != "" && page < githubEventsMaxPages; page++ {
			var events []githubEvent
			resp, err := cli.getJSON(ctx, next, &events)
			if err != nil {
				if isCtxErr(err) {
					return err
				}
				failures = append(failures, engine.ScanFailure{Kind: engine.FailureSource, Source: "github:events/" + login, Err: err})
				break
			}
			older := false
			for _, ev := range events {
				if !since.IsZero() {
					if ts, err := time.Parse(time.RFC3339, ev.CreatedAt); err == nil && ts.Before(since) {
						older = true // feed is newest-first
						continue
					}
				}
				text := githubEventText(ev.Payload)
				if text == "" {
					continue
				}
				owner, repoName, _ := strings.Cut(ev.Repo.Name, "/")
				path := "event:" + ev.ID
				meta := sources.Metadata{GitHub: &sources.GitHubMeta{
					Repository: ev.Repo.Name, Owner: owner, Repo: repoName,
					File: path, Path: path, Entity: "event", Part: ev.Type,
					Visibility: "public",
				}}
				if err := emit([]byte(text), meta); err != nil {
					return err
				}
			}
			if older {
				break
			}
			next = parseLinkHeader(resp.Header.Get("Link"))
		}
	}
	if len(failures) > 0 {
		return &engine.DegradedError{Total: len(failures), Counts: map[engine.FailureKind]int{engine.FailureSource: len(failures)}, Failures: failures}
	}
	return nil
}

// githubEventText collects every string value in an event payload, in a
// deterministic key order, one per line. URLs and API links are dropped:
// they never carry operator-authored text and only add noise.
func githubEventText(raw json.RawMessage) string {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return ""
	}
	var lines []string
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(k, t[k])
			}
		case []any:
			for _, e := range t {
				walk(key, e)
			}
		case string:
			if t == "" || key == "url" || strings.HasSuffix(key, "_url") || key == "node_id" || key == "sha" || key == "head" || key == "before" {
				return
			}
			lines = append(lines, t)
		}
	}
	walk("", v)
	return strings.Join(lines, "\n")
}
