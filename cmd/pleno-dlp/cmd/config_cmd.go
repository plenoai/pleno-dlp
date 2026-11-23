package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

// configVersion is the only accepted `version:` in a pleno-dlp config file.
const configVersion = 1

// projectConfig is the on-disk shape of pleno-dlp.yaml. Keys under `scan`
// are scan flag names without the leading dashes; values are scalars or
// lists. Lists are additive with the CLI, scalars apply only when the flag
// was not passed (CLI > config > built-in default).
type projectConfig struct {
	Version int                  `yaml:"version"`
	Scan    map[string]yaml.Node `yaml:"scan"`
}

var scanConfigPath string

// configDeniedFlag reports flags that must not live in a shared config
// file: credentials, and per-run targets/side files.
func configDeniedFlag(name string) bool {
	for _, frag := range []string{"token", "password", "secret", "api-key", "private-key", "credential"} {
		if strings.Contains(name, frag) {
			return true
		}
	}
	switch name {
	case "config", "repo", "git-url", "cpu-profile", "help":
		return true
	}
	return false
}

func isListFlag(f *pflag.Flag) bool {
	_, ok := f.Value.(pflag.SliceValue)
	return ok
}

// loadProjectConfig reads path and applies it to cmd's flags.
func loadProjectConfig(cmd *cobra.Command, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("--config: %w", err)
	}
	var cfg projectConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("--config %s: %w", path, err)
	}
	if cfg.Version != configVersion {
		return fmt.Errorf("--config %s: version must be %d (got %d)", path, configVersion, cfg.Version)
	}
	keys := make([]string, 0, len(cfg.Scan))
	for k := range cfg.Scan {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		node := cfg.Scan[key]
		if configDeniedFlag(key) {
			return fmt.Errorf("--config %s: scan.%s is not allowed in a config file (credentials and scan targets stay on the command line or in the environment)", path, key)
		}
		f := cmd.Flags().Lookup(key)
		if f == nil {
			return fmt.Errorf("--config %s: scan.%s is not a flag of %q", path, key, cmd.CommandPath())
		}
		var vals []string
		switch node.Kind {
		case yaml.ScalarNode:
			vals = []string{node.Value}
		case yaml.SequenceNode:
			if !isListFlag(f) {
				return fmt.Errorf("--config %s: scan.%s takes a single value, not a list", path, key)
			}
			for _, item := range node.Content {
				if item.Kind != yaml.ScalarNode {
					return fmt.Errorf("--config %s: scan.%s list items must be scalars", path, key)
				}
				vals = append(vals, item.Value)
			}
		default:
			return fmt.Errorf("--config %s: scan.%s must be a scalar or a list", path, key)
		}
		if f.Changed && !isListFlag(f) {
			continue // CLI wins for scalars.
		}
		for _, v := range vals {
			if sv, ok := f.Value.(pflag.SliceValue); ok && !f.Changed {
				// Replace the built-in default with the config list, then
				// let later CLI-less items append.
				if err := sv.Replace(vals); err != nil {
					return fmt.Errorf("--config %s: scan.%s: %w", path, key, err)
				}
				break
			}
			if err := f.Value.Set(v); err != nil {
				return fmt.Errorf("--config %s: scan.%s: %w", path, key, err)
			}
		}
	}
	return nil
}

func scanConfigPreRun(cmd *cobra.Command, _ []string) error {
	path := scanConfigPath
	if path == "" {
		path = os.Getenv("PLENO_DLP_CONFIG")
	}
	if path == "" {
		return nil
	}
	return loadProjectConfig(cmd, path)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate project configuration for `pleno-dlp scan --config`",
}

var configInitOpts struct {
	out   string
	force bool
}

var configInitCmd = &cobra.Command{
	Use:   "init [scan flags...]",
	Short: "Emit a pleno-dlp.yaml from scan flags",
	Long: "Emit a pleno-dlp.yaml containing exactly the scan flags you pass (built-in\n" +
		"defaults are omitted). Load it with `pleno-dlp scan <kind> --config FILE`.\n" +
		"Credentials and scan targets are rejected. Precedence on load:\n" +
		"CLI flag > config file > built-in default; list flags are additive.\n\n" +
		"  pleno-dlp config init --format sarif --fail-on medium --exclude-detectors uri --out pleno-dlp.yaml",
	DisableFlagParsing: true,
	RunE:               runConfigInit,
}

func init() {
	Root.AddCommand(configCmd)
	configCmd.AddCommand(configInitCmd)
	scanCmd.PersistentFlags().StringVar(&scanConfigPath, "config", "",
		"load scan flag defaults from a pleno-dlp.yaml (see pleno-dlp config init; falls back to PLENO_DLP_CONFIG). CLI flags win; list flags are additive")
	scanCmd.PersistentPreRunE = scanConfigPreRun
}

// recordValue captures raw flag values for config init without touching
// the live scan options.
type recordValue struct {
	typ  string
	list bool
	vals []string
}

func (r *recordValue) String() string { return strings.Join(r.vals, ",") }
func (r *recordValue) Type() string   { return r.typ }
func (r *recordValue) Set(s string) error {
	if r.list && strings.HasSuffix(r.typ, "Slice") {
		r.vals = append(r.vals, strings.Split(s, ",")...)
	} else if r.list {
		r.vals = append(r.vals, s)
	} else {
		r.vals = []string{s}
	}
	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	fs := pflag.NewFlagSet("config init", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVarP(&configInitOpts.out, "out", "o", "", "write to this file instead of stdout")
	fs.BoolVar(&configInitOpts.force, "force", false, "overwrite --out if it exists")
	help := fs.BoolP("help", "h", false, "help")
	recs := map[string]*recordValue{}
	scanCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if configDeniedFlag(f.Name) {
			return
		}
		r := &recordValue{typ: f.Value.Type(), list: isListFlag(f)}
		recs[f.Name] = r
		nf := fs.VarPF(r, f.Name, "", f.Usage)
		nf.NoOptDefVal = f.NoOptDefVal
	})
	configInitOpts.out, configInitOpts.force = "", false
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("config init: %w (credentials and scan targets cannot be stored)", err)
	}
	if *help {
		return cmd.Help()
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("config init: unexpected arguments %v (pass scan flags only; targets stay on the command line)", fs.Args())
	}
	scan := map[string]any{}
	fs.Visit(func(f *pflag.Flag) {
		r, ok := recs[f.Name]
		if !ok {
			return
		}
		if r.list {
			scan[f.Name] = r.vals
		} else {
			scan[f.Name] = r.vals[0]
		}
	})
	var buf bytes.Buffer
	buf.WriteString("# pleno-dlp project configuration — load with `pleno-dlp scan <kind> --config <file>`.\n")
	buf.WriteString("# Precedence: CLI flag > this file > built-in default; list values are additive.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(map[string]any{"version": configVersion, "scan": scan}); err != nil {
		return err
	}
	if configInitOpts.out == "" {
		_, err := cmd.OutOrStdout().Write(buf.Bytes())
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if configInitOpts.force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	fh, err := os.OpenFile(configInitOpts.out, flags, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("config init: %s exists (pass --force to overwrite)", configInitOpts.out)
		}
		return err
	}
	if _, err := fh.Write(buf.Bytes()); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}
