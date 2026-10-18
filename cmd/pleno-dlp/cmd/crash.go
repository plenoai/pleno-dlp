// Crash telemetry (issue #497) and the invocation description it records.
//
// This is deliberately local-only: a panic writes a small, secret-free
// report to a path the operator chooses (or nothing at all if they do not
// opt in). Nothing is ever sent anywhere. The report never records a flag
// *value*, only the command path and flag *names*, because values routinely
// carry credentials, repository names, or private filesystem paths
// (`--token`, `--repo`, `--rules`, ...).
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// crashReportFlagName is the root persistent flag that opts a process into
// writing a crash report. The empty default leaves panic behaviour
// completely untouched.
const crashReportFlagName = "crash-report"

// crashReportPath is bound to crashReportFlagName. It is read by the panic
// recovery installed in Execute.
var crashReportPath string

func init() {
	Root.PersistentFlags().StringVar(&crashReportPath, crashReportFlagName, "",
		"write a local, secret-free crash report to this path if pleno-dlp panics "+
			"(disabled by default). The report records the command path, flag names "+
			"(never flag values), version, and stack trace; it is never sent anywhere.")
}

// DescribeInvocation renders a secret-free description of a command line for
// a crash report: the resolved command path followed by every flag name that
// appears in args, in first-seen order. Flags are collected from the whole
// argument list, so a root/persistent flag given *before* the subcommand is
// recorded too (the #497 bug: only flags after the subcommand survived).
//
// A flag's value is never included. `--format=json` contributes `--format`,
// and a separated value (`--repo org/repo`) is skipped entirely. args must
// not include the program name, matching cobra's Root.SetArgs convention
// (i.e. pass os.Args[1:]).
func DescribeInvocation(args []string) string {
	knownValue := invocationValueFlags()
	path := describeCommandPath(args, knownValue)
	flags := invocationFlagNames(args)
	if len(flags) == 0 {
		return path
	}
	return path + " " + strings.Join(flags, " ")
}

// invocationValueFlags returns the set of long and short flag spellings that
// consume a following argument (i.e. do not have a NoOptDefVal). It is built
// once per DescribeInvocation call from the live command tree; the set is
// never mutated, so the lookup is safe to share.
func invocationValueFlags() map[string]bool {
	value := map[string]bool{}
	add := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) {
			if f.NoOptDefVal != "" {
				return
			}
			value["--"+f.Name] = true
			if f.Shorthand != "" {
				value["-"+f.Shorthand] = true
			}
		})
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		// Visit both sets: cobra only folds a command's persistent flags
		// into Flags() during Parse/Find, so before the first Execute the
		// root's persistent flags (e.g. --crash-report) live only in
		// PersistentFlags().
		add(c.Flags())
		add(c.PersistentFlags())
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(Root)
	return value
}

// describeCommandPath walks args the way cobra resolves a command, returning
// the resolved command path ("pleno-dlp scan github"). It only ever consumes
// known value-taking flags' arguments, so an unknown flag or a positional
// argument stops resolution rather than being mistaken for a subcommand.
func describeCommandPath(args []string, knownValue map[string]bool) string {
	// Tolerate callers that pass a full argv (program name first) even
	// though cobra's convention — and the documented contract above — is
	// to exclude it.
	if len(args) > 0 && args[0] == Root.Name() {
		args = args[1:]
	}
	path := []string{Root.Name()}
	cur := Root
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			name := arg
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
			}
			if !strings.Contains(arg, "=") && knownValue[name] && i+1 < len(args) {
				i++ // skip the flag's value
			}
			continue
		}
		next := subcommandOf(cur, arg)
		if next == nil {
			break
		}
		path = append(path, next.Name())
		cur = next
	}
	return strings.Join(path, " ")
}

// subcommandOf resolves a direct child of c by name or alias.
func subcommandOf(c *cobra.Command, name string) *cobra.Command {
	for _, sub := range c.Commands() {
		if sub.Name() == name {
			return sub
		}
		for _, alias := range sub.Aliases {
			if alias == name {
				return sub
			}
		}
	}
	return nil
}

// invocationFlagNames returns every distinct flag spelling in args, in
// first-seen order. A token is treated as a flag if it starts with '-' and
// is longer than one byte; `--flag=value` is trimmed to `--flag`. This is
// intentionally more permissive than the command tree so an unrecognized
// flag is still recorded for a crash report rather than silently dropped.
func invocationFlagNames(args []string) []string {
	seen := make(map[string]bool, len(args))
	names := make([]string, 0, len(args))
	for _, arg := range args {
		if len(arg) < 2 || arg[0] != '-' {
			continue
		}
		name := arg
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if name == "--" || name == "-" {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// crashReport is the on-disk schema. It is intentionally small and stable:
// enough to attribute and reproduce a failure without any secret material.
type crashReport struct {
	Schema     int    `json:"schema"`
	Timestamp  string `json:"timestamp"`
	Version    string `json:"version"`
	Commit     string `json:"commit,omitempty"`
	GoVersion  string `json:"go_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Invocation string `json:"invocation"`
	Panic      string `json:"panic"`
	Stack      string `json:"stack"`
}

// newCrashReport builds a report for a recovered panic value. invocation is
// supplied by the caller so tests (and future non-os.Args callers) can pin
// it; production passes DescribeInvocation(os.Args[1:]).
func newCrashReport(panicValue any, invocation string) crashReport {
	return crashReport{
		Schema:     1,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Version:    toolVersion,
		Commit:     toolCommit,
		GoVersion:  runtime.Version(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Invocation: invocation,
		Panic:      fmt.Sprint(panicValue),
		Stack:      string(debug.Stack()),
	}
}

// writeCrashReport serializes r to path, creating parent directories 0700
// and the file 0600 — a report can contain local paths even though it never
// contains flag values.
func writeCrashReport(path string, r crashReport) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("crash-report: encode: %w", err)
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("crash-report: create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("crash-report: write %s: %w", path, err)
	}
	return nil
}

// handleCrash is the panic path used by Execute. When the operator did not
// opt in it re-panics unchanged, preserving normal Go crash behaviour;
// when they did, it writes the report and returns a plain error so main.go
// still exits non-zero with a readable message.
func handleCrash(panicValue any) error {
	if crashReportPath == "" {
		panic(panicValue)
	}
	report := newCrashReport(panicValue, DescribeInvocation(os.Args[1:]))
	if err := writeCrashReport(crashReportPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "pleno-dlp: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "pleno-dlp: crash report written to %s\n", crashReportPath)
	}
	return fmt.Errorf("internal error: %v", panicValue)
}
