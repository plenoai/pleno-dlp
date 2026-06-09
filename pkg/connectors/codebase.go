package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const codebaseDefaultMaxCommentBytes = int64(1024 * 1024)

func init() {
	Register("codebase", Connector{
		SourceType:  sources.SourceCodebase,
		Scan:        scanCodebase,
		Fingerprint: fingerprintCodebase,
	})
}

func scanCodebase(ctx context.Context, cfg Config, emit Emit) error {
	project, repo, ok := splitOwnerRepo(cfg["repo"])
	if !ok {
		return fmt.Errorf("codebase: --repo must be in project/repository form")
	}
	account := cfg["account"]
	username := cfg["username"]
	apiKey := cfg["token"]
	if account == "" || username == "" || apiKey == "" {
		return fmt.Errorf("codebase: --account, --username and --token are required")
	}
	apiBase := cfg.Get("api_base", "https://api3.codebasehq.com")
	if u, err := url.Parse(apiBase); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("codebase: invalid https api_base %q", apiBase)
	}
	maxBytes := codebaseDefaultMaxCommentBytes
	if v := cfg["max_comment_bytes"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}

	cli := newCodebaseClient(apiBase, account, username, apiKey)
	previousState, err := loadForgeIncrementalState(cfg[configKeyIncrementalPreviousState], "codebase")
	if err != nil {
		return err
	}
	nextState := &forgeIncrementalState{Version: 1, Objects: map[string]forgeObjectIncrementalState{}}
	if previousState == nil {
		previousState = &forgeIncrementalState{Version: 1, Objects: map[string]forgeObjectIncrementalState{}}
	}
	scanState := forgeScanState{previous: previousState, next: nextState}
	if err := scanCodebaseTickets(ctx, cli, project, maxBytes, &scanState, emit); err != nil {
		return err
	}
	if err := scanCodebaseMergeRequests(ctx, cli, project, repo, maxBytes, &scanState, emit); err != nil {
		return err
	}
	data, err := json.Marshal(nextState)
	if err != nil {
		return fmt.Errorf("codebase: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	return nil
}

func fingerprintCodebase(ctx context.Context, cfg Config) (string, error) {
	project, repo, ok := splitOwnerRepo(cfg["repo"])
	if !ok {
		return "", fmt.Errorf("codebase: --repo must be in project/repository form")
	}
	account := cfg["account"]
	username := cfg["username"]
	apiKey := cfg["token"]
	if account == "" || username == "" || apiKey == "" {
		return "", fmt.Errorf("codebase: --account, --username and --token are required")
	}
	apiBase := cfg.Get("api_base", "https://api3.codebasehq.com")
	cli := newCodebaseClient(apiBase, account, username, apiKey)
	h := sha256.New()
	writeFingerprint(h, "codebase-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, project+"/"+repo)
	if err := fingerprintCodebaseTickets(ctx, h, cli, project); err != nil {
		return "", err
	}
	if err := fingerprintCodebaseMergeRequests(ctx, h, cli, project, repo); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type codebaseTicketList struct {
	Tickets []codebaseTicket `xml:"ticket"`
}

type codebaseTicket struct {
	ID int64 `xml:"id"`
}

type codebaseTicketNotes struct {
	Notes []codebaseTicketNote `xml:"ticket-note"`
}

type codebaseTicketNote struct {
	ID      int64  `xml:"id"`
	Content string `xml:"content"`
}

type codebaseMergeRequestList struct {
	MergeRequests []codebaseMergeRequestSummary `xml:"merge-request"`
}

type codebaseMergeRequestSummary struct {
	ID int64 `xml:"id"`
}

type codebaseMergeRequest struct {
	ID       int64                  `xml:"id"`
	Comments []codebaseMergeComment `xml:"comments>comment"`
}

type codebaseMergeComment struct {
	Content string `xml:"content"`
}

func scanCodebaseTickets(ctx context.Context, cli *codebaseClient, project string, maxBytes int64, state *forgeScanState, emit Emit) error {
	for page := 1; ; page++ {
		var list codebaseTicketList
		if err := cli.getXML(ctx, fmt.Sprintf("/%s/tickets?page=%d", url.PathEscape(project), page), &list); err != nil {
			if codebaseIsNotFound(err) && page > 1 {
				return nil
			}
			return fmt.Errorf("codebase: list tickets for %s: %w", project, err)
		}
		if len(list.Tickets) == 0 {
			return nil
		}
		for _, ticket := range list.Tickets {
			var notes codebaseTicketNotes
			if err := cli.getXML(ctx, fmt.Sprintf("/%s/tickets/%d/notes", url.PathEscape(project), ticket.ID), &notes); err != nil {
				return fmt.Errorf("codebase: list notes for ticket %d: %w", ticket.ID, err)
			}
			for _, note := range notes.Notes {
				if err := emitCodebasePart(note.Content, maxBytes, state, sources.ForgeMeta{
					Provider:   "codebase",
					Repository: project,
					File:       fmt.Sprintf("ticket:%d:note:%d", ticket.ID, note.ID),
					Line:       1,
				}, emit); err != nil {
					return err
				}
			}
		}
	}
}

func scanCodebaseMergeRequests(ctx context.Context, cli *codebaseClient, project, repo string, maxBytes int64, state *forgeScanState, emit Emit) error {
	var list codebaseMergeRequestList
	base := fmt.Sprintf("/%s/%s/merge_requests", url.PathEscape(project), url.PathEscape(repo))
	if err := cli.getXML(ctx, base, &list); err != nil {
		return fmt.Errorf("codebase: list merge requests for %s/%s: %w", project, repo, err)
	}
	for _, summary := range list.MergeRequests {
		var mr codebaseMergeRequest
		if err := cli.getXML(ctx, fmt.Sprintf("%s/%d", base, summary.ID), &mr); err != nil {
			return fmt.Errorf("codebase: get merge request %d: %w", summary.ID, err)
		}
		for i, comment := range mr.Comments {
			if err := emitCodebasePart(comment.Content, maxBytes, state, sources.ForgeMeta{
				Provider:   "codebase",
				Repository: project + "/" + repo,
				File:       fmt.Sprintf("merge-request:%d:comment:%d", mr.ID, i+1),
				Line:       1,
			}, emit); err != nil {
				return err
			}
		}
	}
	return nil
}

func fingerprintCodebaseTickets(ctx context.Context, h hash.Hash, cli *codebaseClient, project string) error {
	for page := 1; ; page++ {
		var list codebaseTicketList
		if err := cli.getXML(ctx, fmt.Sprintf("/%s/tickets?page=%d", url.PathEscape(project), page), &list); err != nil {
			if codebaseIsNotFound(err) && page > 1 {
				return nil
			}
			return fmt.Errorf("codebase: list tickets for %s: %w", project, err)
		}
		if len(list.Tickets) == 0 {
			return nil
		}
		for _, ticket := range list.Tickets {
			var notes codebaseTicketNotes
			if err := cli.getXML(ctx, fmt.Sprintf("/%s/tickets/%d/notes", url.PathEscape(project), ticket.ID), &notes); err != nil {
				return fmt.Errorf("codebase: list notes for ticket %d: %w", ticket.ID, err)
			}
			for _, note := range notes.Notes {
				writeFingerprint(h, fmt.Sprintf("ticket:%d:note:%d", ticket.ID, note.ID))
				writeFingerprint(h, note.Content)
			}
		}
	}
}

func fingerprintCodebaseMergeRequests(ctx context.Context, h hash.Hash, cli *codebaseClient, project, repo string) error {
	var list codebaseMergeRequestList
	base := fmt.Sprintf("/%s/%s/merge_requests", url.PathEscape(project), url.PathEscape(repo))
	if err := cli.getXML(ctx, base, &list); err != nil {
		return fmt.Errorf("codebase: list merge requests for %s/%s: %w", project, repo, err)
	}
	for _, summary := range list.MergeRequests {
		var mr codebaseMergeRequest
		if err := cli.getXML(ctx, fmt.Sprintf("%s/%d", base, summary.ID), &mr); err != nil {
			return fmt.Errorf("codebase: get merge request %d: %w", summary.ID, err)
		}
		for i, comment := range mr.Comments {
			writeFingerprint(h, fmt.Sprintf("merge-request:%d:comment:%d", mr.ID, i+1))
			writeFingerprint(h, comment.Content)
		}
	}
	return nil
}

func emitCodebasePart(text string, maxBytes int64, state *forgeScanState, meta sources.ForgeMeta, emit Emit) error {
	text = strings.TrimSpace(text)
	if text == "" || int64(len(text)) > maxBytes {
		return nil
	}
	return emitForgePartIncremental(text, state, meta, emit)
}

type codebaseClient struct {
	base     string
	account  string
	username string
	apiKey   string
	http     *http.Client
}

func newCodebaseClient(base, account, username, apiKey string) *codebaseClient {
	return &codebaseClient{
		base:     strings.TrimRight(base, "/"),
		account:  account,
		username: username,
		apiKey:   apiKey,
		http:     &http.Client{Timeout: 60 * time.Second},
	}
}

type codebaseHTTPError struct {
	status int
	body   string
}

func (e codebaseHTTPError) Error() string {
	return fmt.Sprintf("status %d: %s", e.status, e.body)
}

func codebaseIsNotFound(err error) bool {
	e, ok := err.(codebaseHTTPError)
	return ok && e.status == http.StatusNotFound
}

func (c *codebaseClient) getXML(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/xml")
	req.Header.Set("Content-Type", "application/xml")
	req.SetBasicAuth(c.account+"/"+c.username, c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return codebaseHTTPError{status: resp.StatusCode, body: strings.TrimSpace(string(body))}
	}
	return xml.NewDecoder(resp.Body).Decode(out)
}
