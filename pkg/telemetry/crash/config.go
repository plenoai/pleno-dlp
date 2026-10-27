package crash

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DefaultEndpoint is the open-source relay (plenoai/plenoai.com
// workers/crash-relay) that receives opted-in reports.
const DefaultEndpoint = "https://crash.plenoai.com/v1/pleno-dlp"

// Environment variables that control telemetry.
const (
	EnvReports  = "PLENO_DLP_CRASH_REPORTS"  // "0"/"1" overrides the config file
	EnvEndpoint = "PLENO_DLP_CRASH_ENDPOINT" // overrides the endpoint
	EnvDir      = "PLENO_DLP_TELEMETRY_DIR"  // overrides the config/spool root
)

const configFile = "telemetry.json"

// Source names where the effective enabled bit came from.
type Source string

const (
	SourceDefault Source = "default"
	SourceFile    Source = "file"
	SourceEnv     Source = "env"
)

// fileConfig is the on-disk shape of telemetry.json.
type fileConfig struct {
	CrashReports bool   `json:"crash_reports"`
	Endpoint     string `json:"endpoint,omitempty"`
}

// Config is the resolved telemetry configuration.
type Config struct {
	Enabled  bool
	Source   Source
	Endpoint string
	// Dir is the root holding telemetry.json and crash/.
	Dir string
}

// SpoolDir is where reports are written.
func (c Config) SpoolDir() string { return filepath.Join(c.Dir, "crash") }

// Dir resolves the telemetry root: $PLENO_DLP_TELEMETRY_DIR, else
// os.UserConfigDir()/pleno-dlp.
func Dir(getenv func(string) string) (string, error) {
	if d := getenv(EnvDir); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "pleno-dlp"), nil
}

// Load resolves the configuration. Precedence: env, file, default
// (disabled). A malformed file is an error so a typo cannot silently flip
// the operator's choice.
func Load(getenv func(string) string) (Config, error) {
	dir, err := Dir(getenv)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{Source: SourceDefault, Endpoint: DefaultEndpoint, Dir: dir}
	fc, found, err := readFile(dir)
	if err != nil {
		return cfg, err
	}
	if found {
		cfg.Enabled, cfg.Source = fc.CrashReports, SourceFile
		if fc.Endpoint != "" {
			cfg.Endpoint = fc.Endpoint
		}
	}
	switch v := strings.TrimSpace(getenv(EnvReports)); v {
	case "":
	case "1", "true":
		cfg.Enabled, cfg.Source = true, SourceEnv
	case "0", "false":
		cfg.Enabled, cfg.Source = false, SourceEnv
	default:
		return cfg, fmt.Errorf("%s=%q: want 0 or 1", EnvReports, v)
	}
	if e := getenv(EnvEndpoint); e != "" {
		cfg.Endpoint = e
	}
	if err := ValidateEndpoint(cfg.Endpoint); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// ValidateEndpoint requires https, allowing plain http only to loopback so
// local relays and tests work without exposing reports in transit.
func ValidateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("crash endpoint %q: not an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return nil
		}
	}
	return fmt.Errorf("crash endpoint %q: must be https (http allowed only for loopback)", raw)
}

func readFile(dir string) (fileConfig, bool, error) {
	var fc fileConfig
	b, err := os.ReadFile(filepath.Join(dir, configFile))
	if errors.Is(err, fs.ErrNotExist) {
		return fc, false, nil
	}
	if err != nil {
		return fc, false, err
	}
	if err := json.Unmarshal(b, &fc); err != nil {
		return fc, false, fmt.Errorf("%s: %w", filepath.Join(dir, configFile), err)
	}
	return fc, true, nil
}

// SetEnabled persists the opt-in bit, preserving a configured endpoint.
func SetEnabled(getenv func(string) string, enabled bool) (string, error) {
	dir, err := Dir(getenv)
	if err != nil {
		return "", err
	}
	fc, _, err := readFile(dir)
	if err != nil {
		return "", err
	}
	fc.CrashReports = enabled
	b, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, configFile)
	return path, writePrivate(dir, path, append(b, '\n'))
}

// writePrivate atomically writes data with 0600 under a 0700 directory.
func writePrivate(dir, path string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
