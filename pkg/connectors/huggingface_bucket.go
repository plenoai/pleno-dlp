package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// hfBucketMaxObject caps one downloaded bucket object. Larger objects are
// reported as coverage gaps instead of being buffered.
const hfBucketMaxObject = 64 << 20

// hfBucketMaxPages bounds tree pagination so a looping server cannot pin
// the scan forever.
const hfBucketMaxPages = 10000

type hfBucketTarget struct {
	ID     string // owner/name
	Prefix string // optional object prefix, no leading slash
}

type hfBucketEntry struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	OID     string `json:"oid"`
	XetHash string `json:"xetHash"`
	ETag    string `json:"etag"`
}

// parseHFBucket accepts owner/name[/prefix], hf://buckets/owner/name[/prefix]
// and https://<host>/buckets/owner/name[/(tree|blob|resolve)/prefix].
func parseHFBucket(raw string) (hfBucketTarget, error) {
	s := strings.TrimSpace(raw)
	browser := false
	switch {
	case strings.HasPrefix(s, "hf://"):
		s = strings.TrimPrefix(s, "hf://")
		if !strings.HasPrefix(s, "buckets/") {
			return hfBucketTarget{}, fmt.Errorf("huggingface: %q is not an hf://buckets/ URI", raw)
		}
		s = strings.TrimPrefix(s, "buckets/")
	case strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://"):
		u, err := url.Parse(s)
		if err != nil {
			return hfBucketTarget{}, fmt.Errorf("huggingface: invalid bucket URL %q", raw)
		}
		p := strings.TrimPrefix(u.Path, "/")
		p = strings.TrimPrefix(p, "api/")
		if !strings.HasPrefix(p, "buckets/") {
			return hfBucketTarget{}, fmt.Errorf("huggingface: %q is not a bucket URL", raw)
		}
		s = strings.TrimPrefix(p, "buckets/")
		browser = true
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return hfBucketTarget{}, fmt.Errorf("huggingface: bucket must be owner/name, got %q", raw)
	}
	rest := parts[2:]
	// Browser URLs insert a route marker between bucket ID and object path;
	// in a plain handle those are legitimate directory names.
	if browser && len(rest) > 0 && (rest[0] == "tree" || rest[0] == "blob" || rest[0] == "resolve") {
		rest = rest[1:]
	}
	for _, seg := range append(parts[:2:2], rest...) {
		if seg == "." || seg == ".." {
			return hfBucketTarget{}, fmt.Errorf("huggingface: bucket path %q contains dot segments", raw)
		}
	}
	return hfBucketTarget{ID: parts[0] + "/" + parts[1], Prefix: strings.Join(rest, "/")}, nil
}

// hfListBuckets enumerates the buckets owned by a user or organisation. A
// 404 means the server has no bucket API (mirror, older Hub) and is treated
// as zero buckets.
func hfListBuckets(ctx context.Context, cli *hfClient, owner string) ([]string, error) {
	initial := "/api/buckets/" + url.PathEscape(owner)
	var ids []string
	err := hfPaginate(ctx, cli, initial, func(body []byte) error {
		var page []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("huggingface: decode buckets for %s: %w", owner, err)
		}
		for _, b := range page {
			if b.ID != "" {
				ids = append(ids, b.ID)
			}
		}
		return nil
	})
	if err == errHFNotFound {
		return nil, nil
	}
	return ids, err
}

var errHFNotFound = fmt.Errorf("huggingface: not found")

// hfPaginate follows Link rel="next" from path. Every next link must stay
// on the client's origin and on the initial listing path so a hostile
// server cannot redirect the bearer token or widen the scope.
func hfPaginate(ctx context.Context, cli *hfClient, path string, page func([]byte) error) error {
	initialPath := path
	if i := strings.IndexByte(initialPath, '?'); i >= 0 {
		initialPath = initialPath[:i]
	}
	seen := map[string]bool{}
	cur := path
	for n := 0; cur != ""; n++ {
		if n >= hfBucketMaxPages {
			return fmt.Errorf("huggingface: %s exceeded %d pages", initialPath, hfBucketMaxPages)
		}
		if seen[cur] {
			return fmt.Errorf("huggingface: %s repeated a pagination link", initialPath)
		}
		seen[cur] = true
		resp, err := cli.do(ctx, http.MethodGet, cur, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusNotFound && n == 0 {
			resp.Body.Close()
			return errHFNotFound
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return fmt.Errorf("huggingface: GET %s -> %s", initialPath, resp.Status)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if err := page(body); err != nil {
			return err
		}
		next := parseLinkHeader(resp.Header.Get("Link"))
		if next == "" {
			return nil
		}
		full, err := apiURL("huggingface", cli.base, next)
		if err != nil {
			return err
		}
		nu, err := url.Parse(full)
		if err != nil || nu.EscapedPath() != initialPath {
			return fmt.Errorf("huggingface: pagination left listing scope %s", initialPath)
		}
		cur = full
	}
	return nil
}

func hfEscapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// scanHFBucket lists every file under target and emits its content. Listing
// failures and per-object download failures are recorded via fail; only
// context cancellation and emit errors abort.
func scanHFBucket(ctx context.Context, cli *hfClient, target hfBucketTarget, emit Emit, fail func(string, error)) error {
	owner, name, _ := strings.Cut(target.ID, "/")
	idPath := url.PathEscape(owner) + "/" + url.PathEscape(name)
	entries, err := hfBucketTree(ctx, cli, target)
	if err != nil {
		if isCtxErr(err) {
			return err
		}
		fail("huggingface:bucket/"+target.ID, err)
		return nil
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.Type != "file" || e.Path == "" || seen[e.Path] {
			continue
		}
		seen[e.Path] = true
		src := "huggingface:bucket/" + target.ID + "/" + e.Path
		if e.Size > hfBucketMaxObject {
			fail(src, fmt.Errorf("huggingface: object size %d exceeds %d byte cap", e.Size, hfBucketMaxObject))
			continue
		}
		data, err := hfDownload(ctx, cli, "/buckets/"+idPath+"/resolve/"+hfEscapePath(e.Path))
		if err != nil {
			if isCtxErr(err) {
				return err
			}
			fail(src, err)
			continue
		}
		meta := sources.Metadata{HuggingFace: &sources.HuggingFaceMeta{
			Organization: owner,
			Repository:   name,
			RepoType:     "bucket",
			Path:         e.Path,
		}}
		if err := emit(data, meta); err != nil {
			return err
		}
	}
	return nil
}

func hfDownload(ctx context.Context, cli *hfClient, path string) ([]byte, error) {
	resp, err := cli.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("huggingface: download -> %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, hfBucketMaxObject+1))
	if err != nil {
		return nil, err
	}
	if len(data) > hfBucketMaxObject {
		return nil, fmt.Errorf("huggingface: object exceeds %d byte cap", hfBucketMaxObject)
	}
	return data, nil
}

// hfBucketTree lists every entry under target (recursive).
func hfBucketTree(ctx context.Context, cli *hfClient, target hfBucketTarget) ([]hfBucketEntry, error) {
	owner, name, _ := strings.Cut(target.ID, "/")
	tree := "/api/buckets/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/tree"
	if target.Prefix != "" {
		tree += "/" + hfEscapePath(target.Prefix)
	}
	var entries []hfBucketEntry
	err := hfPaginate(ctx, cli, tree+"?recursive=true", func(body []byte) error {
		var page []hfBucketEntry
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("huggingface: decode bucket tree %s: %w", target.ID, err)
		}
		entries = append(entries, page...)
		return nil
	})
	return entries, err
}

// hfFingerprintBuckets returns sorted identity strings for every object in
// the configured and owner-enumerated buckets.
func hfFingerprintBuckets(ctx context.Context, cli *hfClient, owners []string, repo string, cfg Config) ([]string, error) {
	raws := splitList(cfg["bucket"])
	if repo == "" {
		for _, rt := range parseRepoTypes(cfg.Get("repo_types", hfDefaultRepoTypes)) {
			if rt != "bucket" {
				continue
			}
			for _, owner := range owners {
				ids, err := hfListBuckets(ctx, cli, owner)
				if err != nil {
					return nil, err
				}
				raws = append(raws, ids...)
			}
		}
	}
	var out []string
	for _, raw := range raws {
		t, err := parseHFBucket(raw)
		if err != nil {
			return nil, err
		}
		entries, err := hfBucketTree(ctx, cli, t)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Type == "file" {
				out = append(out, fmt.Sprintf("%s/%s\x00%d\x00%s%s%s", t.ID, e.Path, e.Size, e.OID, e.XetHash, e.ETag))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
