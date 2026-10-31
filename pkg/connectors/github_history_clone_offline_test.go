package connectors

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitHubAppGHECloneWalksOfflineWithoutPersistingCredentials(t *testing.T) {
	clearGitConfigEnvironment(t)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	fixture := gitCloneFixtureRepo(t)
	projectRoot := filepath.Join(t.TempDir(), "projects")
	bareRepo := filepath.Join(projectRoot, "acme", "repo.git")
	if err := os.MkdirAll(filepath.Dir(bareRepo), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(realGit, "clone", "--bare", fixture, bareRepo).CombinedOutput(); err != nil {
		t.Fatalf("prepare smart-HTTP fixture: %v: %s", err, output)
	}

	appKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey)})
	const prefix = "/ghe/api/v3"
	const installationToken = "installation-token-fixture-only"
	systemPath := os.Getenv("PATH")
	var installationRequests, cloneInfoRequests, cloneUploadRequests, offlineRequests atomic.Int32
	var cloneOffline atomic.Bool
	var cloneServerError atomic.Value

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cloneOffline.Load() {
			offlineRequests.Add(1)
			http.Error(w, "clone server is offline after successful clone", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == prefix+"/app/installations/42/access_tokens" {
			if r.Method != http.MethodPost || !validFixtureAppJWT(r.Header.Get("Authorization"), &appKey.PublicKey) {
				http.Error(w, "invalid fixture App JWT", http.StatusUnauthorized)
				return
			}
			installationRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token":      installationToken,
				"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			})
			return
		}
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+installationToken)) {
			http.Error(w, "missing installation token", http.StatusUnauthorized)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, prefix)
		switch {
		case path == "/acme/repo.git/info/refs" && r.Method == http.MethodGet:
			cloneInfoRequests.Add(1)
		case path == "/acme/repo.git/git-upload-pack" && r.Method == http.MethodPost:
			cloneUploadRequests.Add(1)
		default:
			http.NotFound(w, r)
			return
		}
		status, body, backendErr := runFixtureGitHTTPBackend(realGit, systemPath, projectRoot, path, r)
		if backendErr != nil {
			cloneServerError.Store(backendErr.Error())
			http.Error(w, "fixture upload-pack failed", http.StatusInternalServerError)
			return
		}
		for key, values := range status.Headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(status.Code)
		if _, err := w.Write(body); err != nil {
			cloneServerError.Store(err.Error())
			return
		}
	}))
	defer server.Close()

	apiBase := server.URL + prefix
	cloneURL := apiBase + "/acme/repo.git"
	if err := validateGitHubAuthenticatedTransport(apiBase, true); err != nil {
		t.Fatalf("loopback GHE API endpoint rejected: %v", err)
	}
	if err := validateGitHubCloneTarget(apiBase, cloneURL); err != nil {
		t.Fatalf("same-origin GHE clone target rejected: %v", err)
	}
	provider, err := newGitHubAppTokenProvider(Config{
		"app_id":              "fixture-app",
		"app_installation_id": "42",
		"app_private_key":     string(privateKey),
		"api_base":            apiBase,
	})
	if err != nil {
		t.Fatal(err)
	}

	argvLog := filepath.Join(t.TempDir(), "git-argv.log")
	wrapperDir := t.TempDir()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(wrapperDir, "git")
	if err := os.Symlink(testBinary, wrapper); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TEST_GIT_ARGV_LOG", argvLog)
	t.Setenv("PLENO_DLP_TEST_GIT_WRAPPER", "1")
	t.Setenv("PLENO_DLP_TEST_REAL_GIT", realGit)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)

	var cloneConfig string
	previousObserver := githubCloneBytesObserver
	githubCloneBytesObserver = func(repoKey string, _ int64) {
		defer cloneOffline.Store(true)
		if repoKey != "acme/repo" {
			return
		}
		for _, line := range strings.Split(mustReadTestFile(t, argvLog), "\n") {
			fields := strings.SplitN(line, "\t", 3)
			if len(fields) != 3 || !strings.HasPrefix(fields[2], "clone --mirror ") {
				continue
			}
			args := strings.Fields(fields[2])
			if len(args) < 2 {
				t.Errorf("captured malformed clone argv: %q", fields[2])
				return
			}
			data, err := os.ReadFile(filepath.Join(args[len(args)-1], "config"))
			if err != nil {
				t.Errorf("read completed clone config: %v", err)
				return
			}
			cloneConfig = string(data)
			return
		}
		t.Error("native clone argv was not captured")
	}
	t.Cleanup(func() { githubCloneBytesObserver = previousObserver })

	repo := githubRepoRef{Name: "repo", DefaultBranch: "master"}
	repo.Owner.Login = "acme"
	var emitted int
	_, err = scanGitHubGitHistory(context.Background(), Config{}, provider, "ghe.example", cloneURL, repo, githubRepoIncrementalState{}, false, nil, func(data []byte, _ sources.Metadata) error {
		if len(data) > 0 {
			emitted++
		}
		return nil
	})
	if err != nil {
		if backendErr := cloneServerError.Load(); backendErr != nil {
			t.Fatalf("clone/offline walk: %v (fixture git-http-backend: %s)", err, backendErr.(string))
		}
		t.Fatalf("clone/offline walk: %v", err)
	}
	if emitted == 0 {
		t.Fatal("offline history walk emitted no locally cloned content")
	}
	if got := installationRequests.Load(); got != 1 {
		t.Fatalf("GitHub App installation-token requests = %d, want 1", got)
	}
	if got := cloneInfoRequests.Load(); got == 0 {
		t.Fatal("native clone did not request the GHE smart-HTTP advertisement")
	}
	if got := cloneUploadRequests.Load(); got == 0 {
		t.Fatal("native clone did not request upload-pack data")
	}
	if got := offlineRequests.Load(); got != 0 {
		t.Fatalf("offline history walk made %d HTTP request(s) after clone completion", got)
	}
	if strings.Contains(cloneConfig, "extraheader") || strings.Contains(cloneConfig, installationToken) {
		t.Fatalf("installation credential was persisted in clone config: %q", cloneConfig)
	}
	logs := mustReadTestFile(t, argvLog)
	if strings.Contains(logs, installationToken) || strings.Contains(logs, base64.StdEncoding.EncodeToString([]byte("x-access-token:"+installationToken))) {
		t.Fatalf("installation credential leaked into Git argv: %q", logs)
	}
	var sawCloneAuth, sawOfflineWalk bool
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			continue
		}
		if strings.HasPrefix(fields[2], "clone --mirror ") && fields[0] == "present" {
			sawCloneAuth = true
		}
		if fields[1] == "1" {
			sawOfflineWalk = true
			if fields[0] != "none" {
				t.Errorf("offline Git subprocess inherited clone auth config: %q", line)
			}
		}
	}
	if !sawCloneAuth {
		t.Fatal("native clone process did not receive auth through its scoped environment")
	}
	if !sawOfflineWalk {
		t.Fatal("history walk did not invoke Git with GIT_NO_LAZY_FETCH=1")
	}
}

func validFixtureAppJWT(header string, key *rsa.PublicKey) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(header, prefix), ".")
	if len(parts) != 3 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
}

// init turns this test binary into a Git wrapper when native Git launches the
// temporary PATH symlink. This avoids requiring an executable shell script in
// a possibly noexec temporary directory while recording no credential values.
func init() {
	if os.Getenv("PLENO_DLP_TEST_GIT_WRAPPER") != "1" || filepath.Base(os.Args[0]) != "git" {
		return
	}
	auth := "none"
	if strings.HasPrefix(os.Getenv("GIT_CONFIG_VALUE_0"), "Authorization: Basic ") {
		auth = "present"
	}
	log, err := os.OpenFile(os.Getenv("TEST_GIT_ARGV_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open Git wrapper log:", err)
		os.Exit(2)
	}
	_, writeErr := fmt.Fprintf(log, "%s\t%s\t%s\n", auth, os.Getenv("GIT_NO_LAZY_FETCH"), strings.Join(os.Args[1:], " "))
	closeErr := log.Close()
	if writeErr != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, "record Git wrapper invocation:", writeErr, closeErr)
		os.Exit(2)
	}
	cmd := exec.Command(os.Getenv("PLENO_DLP_TEST_REAL_GIT"), os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "run real Git:", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func runFixtureGitHTTPBackend(gitBin, systemPath, projectRoot, path string, request *http.Request) (struct {
	Headers http.Header
	Code    int
}, []byte, error) {
	result := struct {
		Headers http.Header
		Code    int
	}{Headers: make(http.Header), Code: http.StatusOK}
	cmd := exec.Command(gitBin, "http-backend")
	cmd.Env = []string{
		"PATH=" + systemPath,
		"GIT_PROJECT_ROOT=" + projectRoot,
		"GIT_HTTP_EXPORT_ALL=1",
		"PATH_INFO=" + path,
		"REQUEST_METHOD=" + request.Method,
		"QUERY_STRING=" + request.URL.RawQuery,
		"CONTENT_TYPE=" + request.Header.Get("Content-Type"),
		"CONTENT_LENGTH=" + request.Header.Get("Content-Length"),
		"REMOTE_ADDR=127.0.0.1",
		"HTTP_GIT_PROTOCOL=" + request.Header.Get("Git-Protocol"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
	}
	cmd.Stdin = request.Body
	var output bytes.Buffer
	cmd.Stdout = &output
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return result, nil, fmt.Errorf("git http-backend: %w: %s", err, stderr.String())
	}
	reader := bufio.NewReader(bytes.NewReader(output.Bytes()))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return result, nil, fmt.Errorf("read CGI response header: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r\n"), ":")
		if !ok {
			return result, nil, fmt.Errorf("malformed CGI header: %q", line)
		}
		if strings.EqualFold(key, "Status") {
			if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &result.Code); err != nil {
				return result, nil, fmt.Errorf("parse CGI status: %w", err)
			}
			continue
		}
		result.Headers.Add(key, strings.TrimSpace(value))
	}
	body, err := io.ReadAll(reader)
	return result, body, err
}

func mustReadTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func clearGitConfigEnvironment(t *testing.T) {
	t.Helper()
	var saved []string
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !strings.HasPrefix(key, "GIT_CONFIG_") {
			continue
		}
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset inherited Git config %s: %v", key, err)
		}
		saved = append(saved, key+"="+value)
	}
	t.Cleanup(func() {
		for _, entry := range saved {
			key, value, _ := strings.Cut(entry, "=")
			_ = os.Setenv(key, value)
		}
	})
}
