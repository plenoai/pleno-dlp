// Jenkins connector. Scans Jenkins job configs and build console logs for secrets.
//
// Surface:
//   - GET /api/json?tree=jobs[name,url] to enumerate top-level jobs (recursive)
//   - GET /job/<name>/config.xml for job configuration
//   - GET /job/<name>/<build>/consoleText for build console output
//
// Auth: Basic (user + API token). Jenkins CSRF tokens are not required for
// read-only GET requests when using API tokens.
//
// Pagination: depth-first job tree traversal; build list is capped to avoid
// unbounded log volume (default: last 5 builds per job).

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
	jenkinsRequestTimeout = 60 * time.Second
	jenkinsMaxBuilds      = 5
	jenkinsMaxConfigBytes = 2 << 20 // 2 MiB
	jenkinsMaxLogBytes    = 4 << 20 // 4 MiB
)

func init() {
	Register("jenkins", Connector{
		SourceType:  sources.SourceJenkins,
		Scan:        scanJenkins,
		Verify:      verifyJenkins,
		Fingerprint: fingerprintJenkins,
	})
}

// scanJenkins enumerates all jobs and emits their config.xml and recent console
// logs as chunks.
//
// cfg keys:
//   - host       (required) Jenkins base URL (e.g. https://jenkins.example.com)
//   - user       (required) Jenkins username
//   - token      (required) Jenkins API token
//   - max_builds max build console logs per job (default 5)
func scanJenkins(ctx context.Context, cfg Config, emit Emit) error {
	cli, err := newJenkinsClient(cfg)
	if err != nil {
		return err
	}

	jobs, err := cli.listJobs(ctx, "")
	if err != nil {
		return fmt.Errorf("jenkins: list jobs: %w", err)
	}

	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := jenkinsEmitJob(ctx, cli, job, emit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
		}
	}
	return nil
}

func jenkinsEmitJob(ctx context.Context, cli *jenkinsClient, job jenkinsJob, emit Emit) error {
	// Emit job config.xml
	config, err := cli.getJobConfig(ctx, job.Name)
	if err == nil && len(config) > 0 {
		meta := sources.Metadata{
			SIEM: &sources.SIEMMeta{
				Provider: "jenkins",
				Host:     cli.host,
				Index:    job.Name,
				EventID:  "config.xml",
				Link:     job.URL + "config.xml",
			},
		}
		if emitErr := emit(config, meta); emitErr != nil {
			if errors.Is(emitErr, context.Canceled) || errors.Is(emitErr, context.DeadlineExceeded) {
				return emitErr
			}
		}
	}

	// Emit recent build console logs
	builds, err := cli.listBuilds(ctx, job.Name)
	if err != nil {
		return nil // non-fatal: job may have no builds
	}
	for _, build := range builds {
		if err := ctx.Err(); err != nil {
			return err
		}
		log, err := cli.getConsoleLog(ctx, job.Name, build.Number)
		if err != nil || len(log) == 0 {
			continue
		}
		buildNum := fmt.Sprintf("%d", build.Number)
		meta := sources.Metadata{
			SIEM: &sources.SIEMMeta{
				Provider: "jenkins",
				Host:     cli.host,
				Index:    job.Name,
				EventID:  "build-" + buildNum,
				Link:     fmt.Sprintf("%s/job/%s/%d/console", cli.host, job.Name, build.Number),
			},
		}
		if emitErr := emit(log, meta); emitErr != nil {
			if errors.Is(emitErr, context.Canceled) || errors.Is(emitErr, context.DeadlineExceeded) {
				return emitErr
			}
		}
	}
	return nil
}

func fingerprintJenkins(ctx context.Context, cfg Config) (string, error) {
	cli, err := newJenkinsClient(cfg)
	if err != nil {
		return "", err
	}
	jobs, err := cli.listJobs(ctx, "")
	if err != nil {
		return "", fmt.Errorf("jenkins: list jobs for fingerprint: %w", err)
	}
	h := sha256.New()
	writeFingerprint(h, "jenkins-v1")
	writeFingerprint(h, cli.host)
	for _, job := range jobs {
		writeFingerprint(h, job.Name)
		writeFingerprint(h, job.URL)
		if config, err := cli.getJobConfig(ctx, job.Name); err == nil {
			sum := sha256.Sum256(config)
			writeFingerprint(h, fmt.Sprintf("%x", sum))
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func verifyJenkins(ctx context.Context, cfg Config, secret string) (bool, error) {
	host := cfg["host"]
	if host == "" {
		return false, errors.New("jenkins: host is required for verification")
	}
	user := cfg["user"]
	if user == "" {
		return false, errors.New("jenkins: user is required for verification")
	}
	tmpCfg := Config{"host": host, "user": user, "token": secret}
	cli, err := newJenkinsClient(tmpCfg)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cli.host+"/api/json", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(cli.user, cli.token)
	resp, err := cli.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// --- internal types ---

type jenkinsClient struct {
	host      string
	user      string
	token     string
	maxBuilds int
	http      *http.Client
}

type jenkinsJob struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Class string `json:"_class"`
}

type jenkinsBuild struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
}

func newJenkinsClient(cfg Config) (*jenkinsClient, error) {
	host := cfg["host"]
	if host == "" {
		return nil, errors.New("jenkins: host is required (set --host or JENKINS_HOST)")
	}
	user := cfg["user"]
	if user == "" {
		return nil, errors.New("jenkins: user is required (set --user or JENKINS_USER)")
	}
	token := cfg["token"]
	if token == "" {
		return nil, errors.New("jenkins: token is required (set --token or JENKINS_TOKEN)")
	}
	maxBuilds := jenkinsMaxBuilds
	return &jenkinsClient{
		host:      strings.TrimRight(host, "/"),
		user:      user,
		token:     token,
		maxBuilds: maxBuilds,
		http:      &http.Client{Timeout: jenkinsRequestTimeout},
	}, nil
}

func (c *jenkinsClient) doGet(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.token)
	return c.http.Do(req)
}

func (c *jenkinsClient) listJobs(ctx context.Context, folderPath string) ([]jenkinsJob, error) {
	path := "/api/json?tree=jobs[name,url,_class]"
	if folderPath != "" {
		path = "/job/" + folderPath + path
	}
	resp, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("jenkins: list jobs -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		Jobs []jenkinsJob `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("jenkins: decode jobs: %w", err)
	}
	return result.Jobs, nil
}

func (c *jenkinsClient) listBuilds(ctx context.Context, jobName string) ([]jenkinsBuild, error) {
	path := fmt.Sprintf("/job/%s/api/json?tree=builds[number,url]{0,%d}", jobName, c.maxBuilds)
	resp, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("jenkins: list builds for %s -> %s: %s", jobName, resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		Builds []jenkinsBuild `json:"builds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("jenkins: decode builds: %w", err)
	}
	return result.Builds, nil
}

func (c *jenkinsClient) getJobConfig(ctx context.Context, jobName string) ([]byte, error) {
	resp, err := c.doGet(ctx, "/job/"+jobName+"/config.xml")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins: get config for %s -> %s", jobName, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, jenkinsMaxConfigBytes))
}

func (c *jenkinsClient) getConsoleLog(ctx context.Context, jobName string, buildNum int) ([]byte, error) {
	path := fmt.Sprintf("/job/%s/%d/consoleText", jobName, buildNum)
	resp, err := c.doGet(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins: get console log %s#%d -> %s", jobName, buildNum, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, jenkinsMaxLogBytes))
}
