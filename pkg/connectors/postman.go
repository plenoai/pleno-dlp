// Postman connector. Scans Postman workspaces, collections, and environments
// for secrets embedded in request headers, bodies, variables, and examples.
//
// Surface:
//   - GET /workspaces to enumerate workspaces
//   - GET /collections?workspace=<id> to list collections per workspace
//   - GET /collections/<uid> to fetch full collection (requests + variables)
//   - GET /environments?workspace=<id> to list environments
//   - GET /environments/<uid> to fetch environment variables
//
// Auth: Postman API key (X-Api-Key header).
// Verify hits GET /me to confirm key validity.
//
// Pagination: workspaces and collections do not paginate (bounded list);
// a future offset/limit may be needed for very large accounts.

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	postmanBaseURL        = "https://api.getpostman.com"
	postmanRequestTimeout = 60 * time.Second
	postmanMaxBodyBytes   = 4 << 20 // 4 MiB
)

func init() {
	Register("postman", Connector{
		SourceType:  sources.SourcePostman,
		Scan:        scanPostman,
		Verify:      verifyPostman,
		Fingerprint: fingerprintPostman,
	})
}

// scanPostman enumerates all accessible workspaces, then for each workspace
// emits every collection item and environment variable block as a chunk.
//
// cfg keys:
//   - api_key    (required) Postman API key
//   - base_url   override https://api.getpostman.com (for testing)
func scanPostman(ctx context.Context, cfg Config, emit Emit) error {
	cli := newPostmanClient(cfg)

	workspaces, err := cli.listWorkspaces(ctx)
	if err != nil {
		return fmt.Errorf("postman: list workspaces: %w", err)
	}

	for _, ws := range workspaces {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := postmanEmitWorkspace(ctx, cli, ws, emit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
		}
	}
	return nil
}

func postmanEmitWorkspace(ctx context.Context, cli *postmanClient, ws postmanWorkspace, emit Emit) error {
	colls, err := cli.listCollections(ctx, ws.ID)
	if err == nil {
		for _, coll := range colls {
			if err := ctx.Err(); err != nil {
				return err
			}
			full, err := cli.getCollection(ctx, coll.UID)
			if err != nil || full == nil {
				continue
			}
			data, err := json.Marshal(full)
			if err != nil {
				continue
			}
			meta := sources.Metadata{
				SIEM: &sources.SIEMMeta{
					Provider: "postman",
					Host:     postmanBaseURL,
					Index:    ws.Name + "/" + coll.Name,
					EventID:  coll.UID,
					Link:     "https://www.postman.com/collection/" + coll.UID,
				},
			}
			if emitErr := emit(data, meta); emitErr != nil {
				if errors.Is(emitErr, context.Canceled) || errors.Is(emitErr, context.DeadlineExceeded) {
					return emitErr
				}
			}
		}
	}

	envs, err := cli.listEnvironments(ctx, ws.ID)
	if err == nil {
		for _, env := range envs {
			if err := ctx.Err(); err != nil {
				return err
			}
			full, err := cli.getEnvironment(ctx, env.UID)
			if err != nil || full == nil {
				continue
			}
			data, err := json.Marshal(full)
			if err != nil {
				continue
			}
			meta := sources.Metadata{
				SIEM: &sources.SIEMMeta{
					Provider: "postman",
					Host:     postmanBaseURL,
					Index:    ws.Name + "/env/" + env.Name,
					EventID:  env.UID,
					Link:     "https://www.postman.com/environment/" + env.UID,
				},
			}
			if emitErr := emit(data, meta); emitErr != nil {
				if errors.Is(emitErr, context.Canceled) || errors.Is(emitErr, context.DeadlineExceeded) {
					return emitErr
				}
			}
		}
	}
	return nil
}

func fingerprintPostman(ctx context.Context, cfg Config) (string, error) {
	cli := newPostmanClient(cfg)
	workspaces, err := cli.listWorkspaces(ctx)
	if err != nil {
		return "", fmt.Errorf("postman: list workspaces for fingerprint: %w", err)
	}
	h := sha256.New()
	writeFingerprint(h, "postman-v1")
	writeFingerprint(h, cli.baseURL)
	for _, ws := range workspaces {
		writeFingerprint(h, ws.ID)
		writeFingerprint(h, ws.Name)
		if colls, err := cli.listCollections(ctx, ws.ID); err == nil {
			for _, c := range colls {
				writeFingerprint(h, c.UID)
				if full, err := cli.getCollection(ctx, c.UID); err == nil && full != nil {
					data, _ := json.Marshal(full)
					sum := sha256.Sum256(data)
					writeFingerprint(h, fmt.Sprintf("%x", sum))
				}
			}
		}
		if envs, err := cli.listEnvironments(ctx, ws.ID); err == nil {
			for _, e := range envs {
				writeFingerprint(h, e.UID)
			}
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func verifyPostman(ctx context.Context, cfg Config, secret string) (bool, error) {
	tmpCfg := Config{"api_key": secret, "base_url": cfg.Get("base_url", postmanBaseURL)}
	cli := newPostmanClient(tmpCfg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cli.baseURL+"/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Api-Key", secret)
	resp, err := cli.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// --- internal types ---

type postmanClient struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

type postmanWorkspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type postmanCollection struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
	ID   string `json:"id"`
}

type postmanEnvironment struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
	ID   string `json:"id"`
}

func newPostmanClient(cfg Config) *postmanClient {
	return &postmanClient{
		apiKey:  cfg["api_key"],
		baseURL: strings.TrimRight(cfg.Get("base_url", postmanBaseURL), "/"),
		http:    &http.Client{Timeout: postmanRequestTimeout},
	}
}

func (c *postmanClient) doGet(ctx context.Context, path string) (*http.Response, error) {
	if c.apiKey == "" {
		return nil, errors.New("postman: api_key is required (set --api-key or POSTMAN_API_KEY)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	return c.http.Do(req)
}

func (c *postmanClient) listWorkspaces(ctx context.Context) ([]postmanWorkspace, error) {
	resp, err := c.doGet(ctx, "/workspaces")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("postman: list workspaces -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		Workspaces []postmanWorkspace `json:"workspaces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("postman: decode workspaces: %w", err)
	}
	return result.Workspaces, nil
}

func (c *postmanClient) listCollections(ctx context.Context, workspaceID string) ([]postmanCollection, error) {
	resp, err := c.doGet(ctx, "/collections?workspace="+workspaceID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("postman: list collections -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		Collections []postmanCollection `json:"collections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("postman: decode collections: %w", err)
	}
	return result.Collections, nil
}

func (c *postmanClient) getCollection(ctx context.Context, uid string) (map[string]any, error) {
	resp, err := c.doGet(ctx, "/collections/"+uid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("postman: get collection %s -> %s", uid, resp.Status)
	}
	var result map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, postmanMaxBodyBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("postman: decode collection %s: %w", uid, err)
	}
	return result, nil
}

func (c *postmanClient) listEnvironments(ctx context.Context, workspaceID string) ([]postmanEnvironment, error) {
	resp, err := c.doGet(ctx, "/environments?workspace="+workspaceID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("postman: list environments -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		Environments []postmanEnvironment `json:"environments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("postman: decode environments: %w", err)
	}
	return result.Environments, nil
}

func (c *postmanClient) getEnvironment(ctx context.Context, uid string) (map[string]any, error) {
	resp, err := c.doGet(ctx, "/environments/"+uid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("postman: get environment %s -> %s", uid, resp.Status)
	}
	var result map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, postmanMaxBodyBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("postman: decode environment %s: %w", uid, err)
	}
	return result, nil
}
