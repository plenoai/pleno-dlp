package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// jiraMaxSubPages bounds comment and changelog pagination per issue.
const jiraMaxSubPages = 1000

type jiraCommentPage struct {
	StartAt    int           `json:"startAt"`
	MaxResults int           `json:"maxResults"`
	Total      int           `json:"total"`
	Comments   []jiraComment `json:"comments"`
}

// jiraFetchComments pages every comment of one issue.
func jiraFetchComments(ctx context.Context, cli *jiraClient, key string) ([]jiraComment, error) {
	var all []jiraComment
	startAt := 0
	for page := 0; page < jiraMaxSubPages; page++ {
		var resp jiraCommentPage
		path := fmt.Sprintf("/rest/api/3/issue/%s/comment?startAt=%d&maxResults=100", url.PathEscape(key), startAt)
		if err := cli.getJSON(ctx, path, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Comments...)
		startAt += len(resp.Comments)
		if len(resp.Comments) == 0 || startAt >= resp.Total {
			return all, nil
		}
	}
	return nil, fmt.Errorf("jira: %s comments exceeded %d pages", key, jiraMaxSubPages)
}

type jiraChangelogPage struct {
	StartAt    int  `json:"startAt"`
	MaxResults int  `json:"maxResults"`
	Total      int  `json:"total"`
	IsLast     bool `json:"isLast"`
	Values     []struct {
		ID    string `json:"id"`
		Items []struct {
			Field      string `json:"field"`
			From       string `json:"from"`
			FromString string `json:"fromString"`
			To         string `json:"to"`
			ToString   string `json:"toString"`
		} `json:"items"`
	} `json:"values"`
}

// jiraScanChangelog pages /rest/api/3/issue/{key}/changelog and emits one
// chunk per history entry: every item's field name with its from/to
// values. Superseded descriptions and edited fields survive only here.
func jiraScanChangelog(ctx context.Context, cli *jiraClient, key string, proj jiraProjectEntry, state *jiraScanState, emit Emit) error {
	startAt := 0
	for page := 0; page < jiraMaxSubPages; page++ {
		var resp jiraChangelogPage
		path := fmt.Sprintf("/rest/api/3/issue/%s/changelog?startAt=%d&maxResults=100", url.PathEscape(key), startAt)
		if err := cli.getJSON(ctx, path, &resp); err != nil {
			return err
		}
		for _, h := range resp.Values {
			var lines []string
			for _, it := range h.Items {
				for _, v := range []string{it.FromString, it.ToString, it.From, it.To} {
					if v = strings.TrimSpace(v); v != "" {
						lines = append(lines, it.Field+": "+v)
					}
				}
			}
			if len(lines) == 0 {
				continue
			}
			raw, _ := json.Marshal(h)
			part := "changelog:" + h.ID
			if err := state.emitIfChanged(jiraObjectKey(key, part), raw, strings.Join(lines, "\n"), sources.Metadata{
				Jira: &sources.JiraMeta{Project: proj.Key, IssueKey: key, Part: part},
			}, emit); err != nil {
				return err
			}
		}
		startAt += len(resp.Values)
		if resp.IsLast || len(resp.Values) == 0 || (resp.Total > 0 && startAt >= resp.Total) {
			return nil
		}
	}
	return fmt.Errorf("jira: %s changelog exceeded %d pages", key, jiraMaxSubPages)
}
