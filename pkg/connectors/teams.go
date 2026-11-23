// Microsoft Teams connector. Scans channel messages and their replies via
// Microsoft Graph.
//
// Surface:
//   - GET /me/joinedTeams (when no team IDs are configured)
//   - GET /teams/{team}/channels
//   - GET /teams/{team}/channels/{channel}/messages
//   - GET /teams/{team}/channels/{channel}/messages/{message}/replies
//
// Auth: OAuth2 access token with ChannelMessage.Read.All (application) or
// ChannelMessage.Read.All + Team.ReadBasic.All (delegated), sent as
// Authorization: Bearer. Pagination follows @odata.nextLink, which is only
// followed when it stays on the configured Graph origin so the token is
// never sent elsewhere.
//
// Incremental: each message and reply is checkpointed on its
// lastModifiedDateTime; unchanged items are not re-emitted. State is
// flushed after every channel.
//
// Upstream reference: mongodb/kingfisher src/teams.rs.

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/termsafe"
)

const (
	teamsDefaultBaseURL     = "https://graph.microsoft.com/v1.0"
	teamsRequestTimeout     = 60 * time.Second
	teamsMaxPageBytes       = 16 << 20
	teamsMessagesPageSize   = "50"
	teamsMaxPagesPerListing = 100000
)

func init() {
	Register("teams", Connector{
		SourceType:  sources.SourceTeams,
		Scan:        scanTeams,
		Verify:      verifyTeams,
		Fingerprint: fingerprintTeams,
	})
}

type teamsClient struct {
	base  *url.URL
	token string
	http  *http.Client
}

type teamsTeam struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type teamsChannel struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type teamsMessage struct {
	ID                   string `json:"id"`
	ReplyToID            string `json:"replyToId"`
	CreatedDateTime      string `json:"createdDateTime"`
	LastModifiedDateTime string `json:"lastModifiedDateTime"`
	DeletedDateTime      string `json:"deletedDateTime"`
	Subject              string `json:"subject"`
	WebURL               string `json:"webUrl"`
	Body                 struct {
		ContentType string `json:"contentType"`
		Content     string `json:"content"`
	} `json:"body"`
	Attachments []struct {
		Name       string `json:"name"`
		ContentURL string `json:"contentUrl"`
		Content    string `json:"content"`
	} `json:"attachments"`
	From struct {
		User struct {
			DisplayName string `json:"displayName"`
		} `json:"user"`
	} `json:"from"`
}

type teamsIncrementalState struct {
	Version  int               `json:"version"`
	Messages map[string]string `json:"messages"` // team/channel/message[/reply] -> lastModifiedDateTime
}

func newTeamsClient(cfg Config) (*teamsClient, error) {
	token := cfg["token"]
	if token == "" {
		return nil, errors.New("teams: token is required (set --token or MS_GRAPH_TOKEN)")
	}
	raw := strings.TrimRight(cfg.Get("base_url", teamsDefaultBaseURL), "/")
	if err := requireSecureEndpoint("teams", raw); err != nil {
		return nil, err
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("teams: invalid base_url %q", raw)
	}
	return &teamsClient{base: base, token: token, http: authenticatedHTTPClient(teamsRequestTimeout)}, nil
}

// resolve turns a relative API path or an @odata.nextLink into a URL,
// refusing links that leave the configured Graph origin.
func (c *teamsClient) resolve(ref string) (string, error) {
	if strings.HasPrefix(ref, "/") {
		return c.base.String() + ref, nil
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", errors.New("teams: malformed @odata.nextLink")
	}
	if u.Scheme != c.base.Scheme || u.Host != c.base.Host {
		return "", fmt.Errorf("teams: refusing @odata.nextLink to foreign origin %s://%s", u.Scheme, u.Host)
	}
	return u.String(), nil
}

// list follows @odata.nextLink until exhausted, decoding each page's value
// array into fn.
func (c *teamsClient) list(ctx context.Context, path, what string, fn func(json.RawMessage) error) error {
	next := path
	for pages := 0; next != "" && pages < teamsMaxPagesPerListing; pages++ {
		target, err := c.resolve(next)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return fmt.Errorf("teams: %s: %w", what, err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("teams: %s: %w", what, err)
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			return fmt.Errorf("teams: %s -> %s: %s", what, resp.Status, strings.TrimSpace(string(b)))
		}
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, teamsMaxPageBytes)).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("teams: decode %s: %w", what, err)
		}
		for _, v := range page.Value {
			if err := fn(v); err != nil {
				return err
			}
		}
		next = page.NextLink
	}
	return nil
}

func (c *teamsClient) teams(ctx context.Context, ids []string) ([]teamsTeam, error) {
	if len(ids) > 0 {
		out := make([]teamsTeam, 0, len(ids))
		for _, id := range ids {
			out = append(out, teamsTeam{ID: id, DisplayName: id})
		}
		return out, nil
	}
	var out []teamsTeam
	err := c.list(ctx, "/me/joinedTeams", "list joined teams", func(v json.RawMessage) error {
		var t teamsTeam
		if err := json.Unmarshal(v, &t); err != nil {
			return err
		}
		out = append(out, t)
		return nil
	})
	return out, err
}

func teamsMessageText(m teamsMessage) string {
	var b strings.Builder
	if m.Subject != "" {
		b.WriteString(m.Subject)
		b.WriteString("\n")
	}
	b.WriteString(m.Body.Content)
	for _, a := range m.Attachments {
		for _, s := range []string{a.Name, a.ContentURL, a.Content} {
			if s != "" {
				b.WriteString("\n")
				b.WriteString(s)
			}
		}
	}
	return b.String()
}

// scanTeams cfg keys:
//   - token     (required) Graph access token
//   - team_ids  comma-separated team IDs (default: /me/joinedTeams)
//   - base_url  override https://graph.microsoft.com/v1.0 (testing / national clouds)
func scanTeams(ctx context.Context, cfg Config, emit Emit) error {
	cli, err := newTeamsClient(cfg)
	if err != nil {
		return err
	}
	previous := teamsIncrementalState{}
	if raw := cfg[configKeyIncrementalPreviousState]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &previous); err != nil {
			return fmt.Errorf("teams: parse incremental source state: %w", err)
		}
	}
	next := teamsIncrementalState{Version: 1, Messages: map[string]string{}}
	flush := IncrementalFlushFromContext(ctx)
	cfg[configKeyIncrementalPartialSafe] = "true"

	teams, err := cli.teams(ctx, splitCSV(cfg["team_ids"]))
	if err != nil {
		return err
	}
	var failures []engine.ScanFailure
	var unchanged int
	// fail records a listing failure as degraded coverage; emit failures
	// and cancellation abort the scan instead.
	fail := func(source string, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		var ee teamsEmitError
		if errors.As(err, &ee) {
			return ee.err
		}
		failures = append(failures, engine.ScanFailure{Kind: engine.FailureSource, Source: source, Err: err})
		return nil
	}

	for _, team := range teams {
		var channels []teamsChannel
		err := cli.list(ctx, "/teams/"+url.PathEscape(team.ID)+"/channels", "list channels", func(v json.RawMessage) error {
			var ch teamsChannel
			if err := json.Unmarshal(v, &ch); err != nil {
				return err
			}
			channels = append(channels, ch)
			return nil
		})
		if err != nil {
			if ferr := fail("teams/"+team.ID, err); ferr != nil {
				return ferr
			}
			continue
		}
		for _, ch := range channels {
			chanPath := "/teams/" + url.PathEscape(team.ID) + "/channels/" + url.PathEscape(ch.ID)
			index := team.DisplayName + "/" + ch.DisplayName
			emitMsg := func(key string, m teamsMessage) error {
				if m.DeletedDateTime != "" {
					return nil
				}
				stamp := m.LastModifiedDateTime
				if stamp == "" {
					stamp = m.CreatedDateTime
				}
				if stamp != "" && previous.Messages[key] == stamp {
					next.Messages[key] = stamp
					unchanged++
					return nil
				}
				text := teamsMessageText(m)
				if strings.TrimSpace(text) != "" {
					if err := emit([]byte(text), sources.Metadata{SIEM: &sources.SIEMMeta{
						Provider:  "teams",
						Host:      cli.base.Host,
						Index:     index,
						EventID:   key,
						Timestamp: stamp,
						Link:      m.WebURL,
					}}); err != nil {
						return teamsEmitError{err}
					}
				}
				if stamp != "" {
					next.Messages[key] = stamp
				}
				return nil
			}
			var parents []teamsMessage
			err := cli.list(ctx, chanPath+"/messages?$top="+teamsMessagesPageSize, "list messages", func(v json.RawMessage) error {
				var m teamsMessage
				if err := json.Unmarshal(v, &m); err != nil {
					return err
				}
				parents = append(parents, m)
				return emitMsg(team.ID+"/"+ch.ID+"/"+m.ID, m)
			})
			if err != nil {
				if ferr := fail("teams/"+team.ID+"/"+ch.ID, err); ferr != nil {
					return ferr
				}
			}
			for _, p := range parents {
				err := cli.list(ctx, chanPath+"/messages/"+url.PathEscape(p.ID)+"/replies?$top="+teamsMessagesPageSize, "list replies", func(v json.RawMessage) error {
					var m teamsMessage
					if err := json.Unmarshal(v, &m); err != nil {
						return err
					}
					return emitMsg(team.ID+"/"+ch.ID+"/"+p.ID+"/"+m.ID, m)
				})
				if err != nil {
					if ferr := fail("teams/"+team.ID+"/"+ch.ID+"/"+p.ID, err); ferr != nil {
						return ferr
					}
				}
			}
			if flush != nil {
				if data, err := json.Marshal(next); err == nil {
					if ferr := flush(data); ferr != nil {
						termsafe.Fprintf(os.Stderr, "WARN: teams incremental flush failed: %v\n", ferr)
					}
				}
			}
		}
	}
	if unchanged > 0 {
		termsafe.Fprintf(os.Stderr, "teams: skipped unchanged=%d\n", unchanged)
	}
	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("teams: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	if len(failures) > 0 {
		return &engine.DegradedError{Total: len(failures), Counts: map[engine.FailureKind]int{engine.FailureSource: len(failures)}, Failures: failures}
	}
	return nil
}

// fingerprintTeams identifies the scanned scope without network calls or
// the token: Graph host plus the configured team list.
func fingerprintTeams(_ context.Context, cfg Config) (string, error) {
	cli, err := newTeamsClient(cfg)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	writeFingerprint(h, "teams-v1")
	writeFingerprint(h, cli.base.String())
	for _, id := range splitCSV(cfg["team_ids"]) {
		writeFingerprint(h, id)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// verifyTeams checks a Graph token against GET /organization, which any
// valid application or delegated token can read.
func verifyTeams(ctx context.Context, cfg Config, secret string) (bool, error) {
	cli, err := newTeamsClient(Config{"token": secret, "base_url": cfg["base_url"]})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cli.base.String()+"/organization", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := cli.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	}
	return false, fmt.Errorf("teams: verify -> %s", resp.Status)
}

// splitCSV splits a comma-separated config value, trimming blanks.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// teamsEmitError marks an error returned by emit so it is not mistaken for
// a recoverable listing failure.
type teamsEmitError struct{ err error }

func (e teamsEmitError) Error() string { return e.err.Error() }
func (e teamsEmitError) Unwrap() error { return e.err }
