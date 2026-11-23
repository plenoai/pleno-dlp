// Azure Blob Storage connector. Scans every blob in one container using a
// Shared Access Signature (SAS) for authorization.
//
// Surface:
//   - GET {container}?restype=container&comp=list (marker pagination)
//   - GET {container}/{blob} for each listed blob
//
// Auth: SAS query string appended to every request. The SAS is a bearer
// credential, so it never appears in error messages, logs, finding
// metadata, or the fingerprint: every transport error is rebuilt without
// the request URL and the SAS is scrubbed from anything echoed back.
//
// Incremental: the per-blob ETag is the checkpoint. A blob whose ETag is
// unchanged since the previous run is skipped; state is flushed after
// every listing page so an interrupted scan resumes where it stopped.
//
// Upstream reference: mongodb/kingfisher src/azure_blob.rs.

package connectors

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/termsafe"
)

const (
	azureBlobAPIVersion      = "2021-08-06"
	azureBlobRequestTimeout  = 120 * time.Second
	azureBlobDefaultMaxBytes = 10 << 20 // 10 MiB, matches the S3/GCS default
	azureBlobListPageSize    = 5000
)

func init() {
	Register("azure-blob", Connector{
		SourceType:  sources.SourceAzureBlob,
		Scan:        scanAzureBlob,
		Fingerprint: fingerprintAzureBlob,
	})
}

type azureBlobIncrementalState struct {
	Version int               `json:"version"`
	ETags   map[string]string `json:"etags"`
}

type azureBlobClient struct {
	container *url.URL // scheme://host/container, no query
	sas       url.Values
	sasRaw    string
	prefix    string
	http      *http.Client
}

type azureBlobItem struct {
	Name       string `xml:"Name"`
	Properties struct {
		ETag          string `xml:"Etag"`
		ContentLength int64  `xml:"Content-Length"`
		ResourceType  string `xml:"ResourceType"`
	} `xml:"Properties"`
}

type azureBlobListResult struct {
	Blobs      []azureBlobItem `xml:"Blobs>Blob"`
	NextMarker string          `xml:"NextMarker"`
}

// newAzureBlobClient builds a client from cfg keys:
//   - container_url (required) https://<account>.blob.core.windows.net/<container>;
//     a SAS query string embedded in the URL is split off and treated as sas_token
//   - sas_token     SAS query string (with or without the leading '?')
//   - prefix        only scan blobs whose name starts with this prefix
func newAzureBlobClient(cfg Config) (*azureBlobClient, error) {
	raw := strings.TrimSpace(cfg["container_url"])
	if raw == "" {
		return nil, errors.New("azure-blob: container_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("azure-blob: container_url is not a valid URL")
	}
	sasRaw := strings.TrimPrefix(strings.TrimSpace(cfg["sas_token"]), "?")
	if u.RawQuery != "" {
		if sasRaw != "" {
			return nil, errors.New("azure-blob: pass the SAS either in container_url or as sas_token, not both")
		}
		sasRaw = u.RawQuery
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = "/" + strings.Trim(u.Path, "/")
	if u.Path == "/" || strings.Contains(strings.TrimPrefix(u.Path, "/"), "/") {
		return nil, fmt.Errorf("azure-blob: container_url must name exactly one container: %q", u.String())
	}
	if err := requireSecureEndpoint("azure-blob", u.String()); err != nil {
		return nil, err
	}
	if sasRaw == "" {
		return nil, errors.New("azure-blob: a SAS token is required (set --sas-token or AZURE_STORAGE_SAS_TOKEN)")
	}
	sas, err := url.ParseQuery(sasRaw)
	if err != nil || sas.Get("sig") == "" {
		return nil, errors.New("azure-blob: SAS token is malformed (missing the sig parameter)")
	}
	return &azureBlobClient{
		container: u,
		sas:       sas,
		sasRaw:    sasRaw,
		prefix:    cfg["prefix"],
		http:      authenticatedHTTPClient(azureBlobRequestTimeout),
	}, nil
}

// redact removes every representation of the SAS from s.
func (c *azureBlobClient) redact(s string) string {
	for _, v := range []string{c.sasRaw, c.sas.Get("sig"), url.QueryEscape(c.sas.Get("sig"))} {
		if v != "" {
			s = strings.ReplaceAll(s, v, "REDACTED")
		}
	}
	return s
}

func (c *azureBlobClient) get(ctx context.Context, path string, extra url.Values, what string) (*http.Response, error) {
	u := *c.container
	u.Path = path
	q := url.Values{}
	for k, v := range c.sas {
		q[k] = v
	}
	for k, v := range extra {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("azure-blob: %s: build request", what)
	}
	req.Header.Set("x-ms-version", azureBlobAPIVersion)
	resp, err := c.http.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// *url.Error embeds the full request URL (and so the SAS); keep
		// only the underlying cause, scrubbed.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, fmt.Errorf("azure-blob: %s: %s", what, c.redact(err.Error()))
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("azure-blob: %s -> %s: %s", what, resp.Status, c.redact(azureBlobErrorCode(b)))
	}
	return resp, nil
}

// azureBlobErrorCode extracts <Code> from a storage error body; the
// <Message>/<AuthenticationErrorDetail> fields can echo the signed string.
func azureBlobErrorCode(body []byte) string {
	var e struct {
		Code string `xml:"Code"`
	}
	if xml.Unmarshal(body, &e) == nil && e.Code != "" {
		return e.Code
	}
	return "unrecognized error body"
}

func (c *azureBlobClient) listPage(ctx context.Context, marker string) (*azureBlobListResult, error) {
	q := url.Values{
		"restype":    {"container"},
		"comp":       {"list"},
		"maxresults": {strconv.Itoa(azureBlobListPageSize)},
	}
	if c.prefix != "" {
		q.Set("prefix", c.prefix)
	}
	if marker != "" {
		q.Set("marker", marker)
	}
	resp, err := c.get(ctx, c.container.Path, q, "list blobs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out azureBlobListResult
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("azure-blob: decode blob listing: %w", err)
	}
	return &out, nil
}

func (c *azureBlobClient) download(ctx context.Context, name string, maxBytes int64) ([]byte, error) {
	resp, err := c.get(ctx, c.container.Path+"/"+name, nil, "get blob "+strconv.Quote(name))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("azure-blob: read blob %q: %s", name, c.redact(err.Error()))
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("azure-blob: blob %q exceeds max size %d", name, maxBytes)
	}
	return b, nil
}

func (c *azureBlobClient) endpoint() string {
	return c.container.Scheme + "://" + c.container.Host
}

func (c *azureBlobClient) containerName() string {
	return strings.TrimPrefix(c.container.Path, "/")
}

func scanAzureBlob(ctx context.Context, cfg Config, emit Emit) error {
	cli, err := newAzureBlobClient(cfg)
	if err != nil {
		return err
	}
	maxBytes := int64(azureBlobDefaultMaxBytes)
	if v := cfg["max_size_bytes"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}
	previous := azureBlobIncrementalState{}
	if raw := cfg[configKeyIncrementalPreviousState]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &previous); err != nil {
			return fmt.Errorf("azure-blob: parse incremental source state: %w", err)
		}
	}
	next := azureBlobIncrementalState{Version: 1, ETags: map[string]string{}}
	flush := IncrementalFlushFromContext(ctx)
	cfg[configKeyIncrementalPartialSafe] = "true"

	var failures []engine.ScanFailure
	var skippedUnchanged, skippedLarge int
	marker := ""
	for {
		page, err := cli.listPage(ctx, marker)
		if err != nil {
			return err
		}
		for _, b := range page.Blobs {
			if err := ctx.Err(); err != nil {
				return err
			}
			if b.Properties.ResourceType == "directory" {
				continue
			}
			etag := b.Properties.ETag
			if etag != "" && previous.ETags[b.Name] == etag {
				next.ETags[b.Name] = etag
				skippedUnchanged++
				continue
			}
			if b.Properties.ContentLength > maxBytes {
				skippedLarge++ // policy skip (--max-size), like the S3/GCS sources
				continue
			}
			data, err := cli.download(ctx, b.Name, maxBytes)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				failures = append(failures, engine.ScanFailure{Kind: engine.FailureSource, Source: cli.containerName() + "/" + b.Name, Err: err})
				continue
			}
			meta := sources.Metadata{AzureBlob: &sources.AzureBlobMeta{
				Endpoint:  cli.endpoint(),
				Container: cli.containerName(),
				Blob:      b.Name,
				ETag:      etag,
			}}
			if err := emit(data, meta); err != nil {
				return err
			}
			if etag != "" {
				next.ETags[b.Name] = etag
			}
		}
		if flush != nil {
			if data, err := json.Marshal(next); err == nil {
				if ferr := flush(data); ferr != nil {
					termsafe.Fprintf(os.Stderr, "WARN: azure-blob incremental flush failed: %v\n", ferr)
				}
			}
		}
		if page.NextMarker == "" {
			break
		}
		marker = page.NextMarker
	}
	if skippedUnchanged > 0 || skippedLarge > 0 {
		termsafe.Fprintf(os.Stderr, "azure-blob: skipped unchanged=%d oversized=%d\n", skippedUnchanged, skippedLarge)
	}
	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("azure-blob: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	if len(failures) > 0 {
		return &engine.DegradedError{Total: len(failures), Counts: map[engine.FailureKind]int{engine.FailureSource: len(failures)}, Failures: failures}
	}
	return nil
}

// fingerprintAzureBlob returns "" — there is no cheap whole-container
// fingerprint, and a scope-only hash would make --incremental skip the
// scan even when blobs changed. The empty fingerprint opts out of the
// skip fast-path; the per-blob ETag state still makes re-scans incremental.
// The config is still validated so --incremental fails fast on bad input.
func fingerprintAzureBlob(_ context.Context, cfg Config) (string, error) {
	if _, err := newAzureBlobClient(cfg); err != nil {
		return "", err
	}
	return "", nil
}
