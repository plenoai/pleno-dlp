// Jira connector. Single-file Lambda-handler shape.
//
// Surface: project enumeration → JQL search → emit one chunk per issue
// description and one per comment body. Both ADF (Cloud) and
// storage-format XHTML (Data Center) bodies parse via the helper
// sub-packages pkg/connectors/jira/{adf,storage}.
//
// Auth: Cloud sends `Authorization: Basic <base64(email:token)>` when
// the email field is populated. Data Center sends
// `Authorization: Bearer <pat>` when email is empty.
//
// Pagination: Jira issue search uses startAt offset / total. Project
// search uses startAt + isLast.

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
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/connectors/jira/adf"
	"github.com/plenoai/pleno-dlp/pkg/connectors/jira/storage"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	jiraRequestTimeout = 60 * time.Second
	jiraPageSize       = 50
)

func init() {
	Register("jira", Connector{
		SourceType:  sources.SourceJira,
		Scan:        scanJira,
		Verify:      verifyJira,
		Fingerprint: fingerprintJira,
	})
}

// scanJira is the Lambda handler. cfg keys:
//   - token     (required) Cloud API token or Data Center PAT
//   - email     Atlassian account email; presence selects Basic auth (Cloud)
//   - api_base  (required) Jira REST root (e.g. https://acme.atlassian.net)
//   - project   single-project filter (mutually exclusive with jql)
//   - jql       raw JQL query (overrides project)
//   - max_results cap on issues scanned across all projects (0 = all)
//   - include_changelog  also scan every issue's change history: each
//     history entry's from/to strings (old descriptions, renamed
//     summaries, edited custom fields) become one chunk
//
// Comments embedded in search results are capped by Jira; when an issue
// reports more comments than were embedded the full list is paged from
// /rest/api/3/issue/{key}/comment. Per-project and per-issue failures are
// engine.DegradedError coverage gaps.
func scanJira(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return errors.New("jira: token is required (set --token or JIRA_TOKEN)")
	}
	apiBase := strings.TrimRight(cfg["api_base"], "/")
	if apiBase == "" {
		return errors.New("jira: api_base is required (set --site or --api-base)")
	}
	if err := requireSecureEndpoint("jira", apiBase); err != nil {
		return err
	}
	cli := newJiraClient(apiBase, cfg["email"], token)

	projects, err := jiraResolveProjects(ctx, cli, cfg["project"], cfg["jql"])
	if err != nil {
		return err
	}
	previousState, err := loadJiraIncrementalState(cfg[configKeyIncrementalPreviousState])
	if err != nil {
		return err
	}
	nextState := &jiraIncrementalState{Version: 1, Objects: map[string]jiraObjectIncrementalState{}}
	if previousState == nil {
		previousState = &jiraIncrementalState{Version: 1, Objects: map[string]jiraObjectIncrementalState{}}
	}
	var failures []engine.ScanFailure
	fail := func(source string, err error) {
		failures = append(failures, engine.ScanFailure{Kind: engine.FailureSource, Source: source, Err: err})
	}
	maxIssues := 0
	if raw := cfg["max_results"]; raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return fmt.Errorf("jira: max_results must be a non-negative integer, got %q", raw)
		}
		maxIssues = n
	}
	scanState := jiraScanState{previous: previousState, next: nextState, changelog: parseBool(cfg["include_changelog"]), fail: fail, maxIssues: maxIssues}
	for _, proj := range projects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scanJiraProject(ctx, cli, proj, cfg["jql"], &scanState, emit); err != nil {
			if errors.Is(err, errJiraMaxIssues) {
				break
			}
			if isCtxErr(err) {
				return err
			}
			fail("jira:"+proj.Key, err)
		}
	}
	data, err := json.Marshal(nextState)
	if err != nil {
		return fmt.Errorf("jira: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	if len(failures) > 0 {
		return &engine.DegradedError{Total: len(failures), Counts: map[engine.FailureKind]int{engine.FailureSource: len(failures)}, Failures: failures}
	}
	return nil
}

func verifyJira(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := strings.TrimRight(cfg["api_base"], "/")
	if apiBase == "" {
		return false, errors.New("jira: api_base not set (use --site or --api-base)")
	}
	if err := requireSecureEndpoint("jira", apiBase); err != nil {
		return false, err
	}
	cli := newJiraClient(apiBase, cfg["email"], secret)
	resp, err := cli.do(ctx, http.MethodGet, "/rest/api/3/myself", nil)
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
		return false, fmt.Errorf("jira: verify unexpected status %s", resp.Status)
	}
}

func fingerprintJira(ctx context.Context, cfg Config) (string, error) {
	token := cfg["token"]
	if token == "" {
		return "", errors.New("jira: token is required (set --token or JIRA_TOKEN)")
	}
	apiBase := strings.TrimRight(cfg["api_base"], "/")
	if apiBase == "" {
		return "", errors.New("jira: api_base is required (set --site or --api-base)")
	}
	if err := requireSecureEndpoint("jira", apiBase); err != nil {
		return "", err
	}
	cli := newJiraClient(apiBase, cfg["email"], token)
	projects, err := jiraResolveProjects(ctx, cli, cfg["project"], cfg["jql"])
	if err != nil {
		return "", err
	}
	h := sha256.New()
	writeFingerprint(h, "jira-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, cfg["project"])
	writeFingerprint(h, cfg["jql"])
	writeFingerprint(h, "changelog="+cfg["include_changelog"])
	for _, proj := range projects {
		if err := fingerprintJiraProject(ctx, h, cli, proj, cfg["jql"]); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fingerprintJiraProject(ctx context.Context, h hash.Hash, cli *jiraClient, proj jiraProjectEntry, rawJQL string) error {
	return forEachJiraIssue(ctx, cli, proj, rawJQL, func(issue jiraIssue) error {
		writeFingerprint(h, issue.Key)
		// updated moves on every comment, edit, and history entry, so it
		// also covers comments beyond the embedded page and the changelog.
		writeFingerprint(h, issue.Fields.Updated)
		writeFingerprint(h, issue.Fields.Summary)
		writeFingerprint(h, string(issue.Fields.Description))
		for _, com := range issue.Fields.Comments.Comments {
			writeFingerprint(h, com.ID)
			writeFingerprint(h, string(com.Body))
		}
		return nil
	})
}

// --- internal types ---

type jiraProjectEntry struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type jiraProjectSearchResp struct {
	Values []struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"values"`
	IsLast  bool `json:"isLast"`
	Total   int  `json:"total"`
	StartAt int  `json:"startAt"`
}

type jiraSearchReq struct {
	JQL        string   `json:"jql"`
	MaxResults int      `json:"maxResults"`
	StartAt    int      `json:"startAt"`
	Fields     []string `json:"fields"`
}

type jiraSearchResp struct {
	StartAt    int         `json:"startAt"`
	MaxResults int         `json:"maxResults"`
	Total      int         `json:"total"`
	Issues     []jiraIssue `json:"issues"`
}

type jiraIssue struct {
	Key    string `json:"key"`
	Fields struct {
		Summary     string             `json:"summary"`
		Updated     string             `json:"updated"`
		Description json.RawMessage    `json:"description"`
		Comments    jiraCommentWrapper `json:"comment"`
	} `json:"fields"`
}

type jiraComment struct {
	ID   string          `json:"id"`
	Body json.RawMessage `json:"body"`
}

type jiraCommentWrapper struct {
	Comments []jiraComment `json:"comments"`
	Total    int           `json:"total"`
}

type jiraIncrementalState struct {
	Version int                                   `json:"version"`
	Objects map[string]jiraObjectIncrementalState `json:"objects"`
}

type jiraObjectIncrementalState struct {
	Hash string `json:"hash,omitempty"`
}

type jiraScanState struct {
	previous  *jiraIncrementalState
	next      *jiraIncrementalState
	changelog bool
	fail      func(source string, err error)
	// maxIssues caps issues scanned across all projects (0 = no cap).
	maxIssues int
	issues    int
}

var errJiraMaxIssues = errors.New("jira: max_results reached")

func (s *jiraScanState) failf(source string, err error) {
	if s != nil && s.fail != nil {
		s.fail(source, err)
	}
}

// emitIfChanged records hash(raw) under key and emits text unless the
// previous run saw the same raw content.
func (s *jiraScanState) emitIfChanged(key string, raw []byte, text string, meta sources.Metadata, emit Emit) error {
	current := jiraStateForRaw(raw)
	if s != nil && s.next != nil {
		s.next.Objects[key] = current
	}
	if s != nil && s.previous != nil && s.previous.Objects[key] == current {
		return nil
	}
	if text == "" {
		return nil
	}
	return emit([]byte(text), meta)
}

func loadJiraIncrementalState(raw string) (*jiraIncrementalState, error) {
	if raw == "" {
		return nil, nil
	}
	var state jiraIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("jira: parse incremental source state: %w", err)
	}
	if state.Objects == nil {
		state.Objects = map[string]jiraObjectIncrementalState{}
	}
	return &state, nil
}

func jiraResolveProjects(ctx context.Context, cli *jiraClient, project, jql string) ([]jiraProjectEntry, error) {
	if jql != "" {
		// Raw JQL — search directly, no project enumeration.
		return []jiraProjectEntry{{Key: "", Name: "jql"}}, nil
	}
	if project != "" {
		return []jiraProjectEntry{{Key: project, Name: project}}, nil
	}
	var projects []jiraProjectEntry
	startAt := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var resp jiraProjectSearchResp
		path := fmt.Sprintf("/rest/api/3/project/search?maxResults=%d&startAt=%d", jiraPageSize, startAt)
		if err := cli.getJSON(ctx, path, &resp); err != nil {
			return nil, fmt.Errorf("jira: list projects: %w", err)
		}
		for _, v := range resp.Values {
			projects = append(projects, jiraProjectEntry{Key: v.Key, Name: v.Name})
		}
		if resp.IsLast || len(resp.Values) == 0 {
			break
		}
		startAt += len(resp.Values)
	}
	if len(projects) == 0 {
		return nil, errors.New("jira: no accessible projects found")
	}
	return projects, nil
}

func scanJiraProject(ctx context.Context, cli *jiraClient, proj jiraProjectEntry, rawJQL string, state *jiraScanState, emit Emit) error {
	return forEachJiraIssue(ctx, cli, proj, rawJQL, func(issue jiraIssue) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if state != nil && state.maxIssues > 0 {
			if state.issues >= state.maxIssues {
				return errJiraMaxIssues
			}
			state.issues++
		}
		if len(issue.Fields.Comments.Comments) < issue.Fields.Comments.Total {
			all, err := jiraFetchComments(ctx, cli, issue.Key)
			if err != nil {
				if isCtxErr(err) {
					return err
				}
				// Keep the embedded page; the rest is a coverage gap.
				state.failf("jira:"+issue.Key+":comments", err)
			} else {
				issue.Fields.Comments.Comments = all
			}
		}
		if err := emitJiraIssueIncremental(issue, proj, state, emit); err != nil {
			return err
		}
		if state != nil && state.changelog {
			if err := jiraScanChangelog(ctx, cli, issue.Key, proj, state, emit); err != nil {
				if isCtxErr(err) {
					return err
				}
				state.failf("jira:"+issue.Key+":changelog", err)
			}
		}
		return nil
	})
}

func forEachJiraIssue(ctx context.Context, cli *jiraClient, proj jiraProjectEntry, rawJQL string, visit func(jiraIssue) error) error {
	jql := rawJQL
	if jql == "" {
		jql = fmt.Sprintf("project = %s", proj.Key)
	}
	startAt := 0
	for {
		body := jiraSearchReq{
			JQL: jql, MaxResults: jiraPageSize, StartAt: startAt,
			Fields: []string{"summary", "description", "comment", "updated"},
		}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("jira: marshal search body: %w", err)
		}
		var resp jiraSearchResp
		if err := cli.postJSON(ctx, "/rest/api/3/search", bodyJSON, &resp); err != nil {
			return fmt.Errorf("jira: search %s: %w", proj.Key, err)
		}
		for _, issue := range resp.Issues {
			if err := visit(issue); err != nil {
				return err
			}
		}
		if startAt+jiraPageSize >= resp.Total {
			break
		}
		startAt += len(resp.Issues)
		if len(resp.Issues) == 0 {
			break
		}
	}
	return nil
}

func emitJiraIssueIncremental(iss jiraIssue, proj jiraProjectEntry, state *jiraScanState, emit Emit) error {
	if summary := strings.TrimSpace(iss.Fields.Summary); summary != "" {
		if err := state.emitIfChanged(jiraObjectKey(iss.Key, "summary"), []byte(summary), summary, sources.Metadata{
			Jira: &sources.JiraMeta{Project: proj.Key, IssueKey: iss.Key, Part: "summary"},
		}, emit); err != nil {
			return err
		}
	}
	if len(iss.Fields.Description) > 0 {
		key := jiraObjectKey(iss.Key, "description")
		current := jiraStateForRaw(iss.Fields.Description)
		if state != nil && state.next != nil {
			state.next.Objects[key] = current
		}
		if state == nil || state.previous == nil || state.previous.Objects[key] != current {
			text := jiraParseContent(iss.Fields.Description)
			if text != "" {
				if err := emit([]byte(text), sources.Metadata{
					Jira: &sources.JiraMeta{Project: proj.Key, IssueKey: iss.Key, Part: "description"},
				}); err != nil {
					return err
				}
			}
		}
	}
	for _, com := range iss.Fields.Comments.Comments {
		if len(com.Body) == 0 {
			continue
		}
		key := jiraObjectKey(iss.Key, "comment:"+com.ID)
		current := jiraStateForRaw(com.Body)
		if state != nil && state.next != nil {
			state.next.Objects[key] = current
		}
		if state != nil && state.previous != nil && state.previous.Objects[key] == current {
			continue
		}
		text := jiraParseContent(com.Body)
		if text == "" {
			continue
		}
		if err := emit([]byte(text), sources.Metadata{
			Jira: &sources.JiraMeta{Project: proj.Key, IssueKey: iss.Key, Part: "comment:" + com.ID},
		}); err != nil {
			return err
		}
	}
	return nil
}

func jiraObjectKey(issueKey, part string) string {
	return issueKey + ":" + part
}

func jiraStateForRaw(raw json.RawMessage) jiraObjectIncrementalState {
	sum := sha256.Sum256(raw)
	return jiraObjectIncrementalState{Hash: hex.EncodeToString(sum[:])}
}

// jiraParseContent dispatches between ADF (Cloud) and storage-format
// XHTML (Data Center) based on the first non-whitespace character.
func jiraParseContent(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	if trimmed[0] == '{' {
		if text, err := adf.ToText(raw); err == nil && text != "" {
			return text
		}
		return trimmed
	}
	if text, err := storage.ToTextString(trimmed); err == nil && text != "" {
		return text
	}
	return trimmed
}

// --- HTTP client ---

type jiraClient struct {
	base  string
	email string
	token string
	http  *http.Client
}

func newJiraClient(base, email, token string) *jiraClient {
	return &jiraClient{
		base:  base,
		email: email,
		token: token,
		http:  authenticatedHTTPClient(jiraRequestTimeout),
	}
}

func (c *jiraClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func (c *jiraClient) getJSON(ctx context.Context, path string, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *jiraClient) postJSON(ctx context.Context, path string, body []byte, out any) error {
	resp, err := c.do(ctx, http.MethodPost, path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("POST %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *jiraClient) setAuth(req *http.Request) {
	if c.email != "" {
		req.SetBasicAuth(c.email, c.token)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}
