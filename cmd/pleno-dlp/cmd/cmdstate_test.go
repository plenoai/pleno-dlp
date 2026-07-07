package cmd

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// resetCommandFlagsNow resets every flag on every command in the Root
// tree to its declared default, including cobra's own lazily-attached
// "help"/"version" bool flags, right now. cobra binds each flag's
// Value to the package-level *Opts struct field it was declared with
// (StringVar, BoolVar, ...), so Value.Set(DefValue) restores that
// field too — one walk fixes both cobra-internal and this package's
// shared state.
//
// Background: #283, following #273/PR #279. cobra's help flag is a
// normal pflag Value on the resolved leaf command; Parse only touches
// flags present in argv, so "--help" sets it true and it stays true
// for every later Execute() of that same command in the process,
// silently short-circuiting real invocations into printing help. The
// same applies to any sticky string/bool flag whose backing struct
// field a test mutates without resetting. Resetting once per test is
// not enough for a test that itself calls Root.Execute() more than
// once with different flags (e.g. --help then a real run): call this
// bare function again between such calls, in addition to
// resetCommandFlags at the top of the test.
func resetCommandFlagsNow() {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.InitDefaultHelpFlag()
		c.InitDefaultVersionFlag()
		c.Flags().VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			// pflag.SliceValue (StringSliceVar, IntSliceVar, ...) is the
			// one type where Set(f.DefValue) is not a safe reset: once a
			// real Parse() has called Set on it, the concrete Value's own
			// internal "changed" bit (private to pflag, distinct from
			// f.Changed above) latches to true and every later Set call
			// appends instead of replacing — Set("") on a leaked
			// ["aws","generichighentropy"] silently no-ops instead of
			// clearing it (#283: this is what let --exclude-detectors
			// from one test filter out the AWS detector in every test
			// that ran afterward in the same binary). Replace bypasses
			// that latch unconditionally, so it is used whenever available.
			if sv, ok := f.Value.(pflag.SliceValue); ok {
				_ = sv.Replace(decodeDefaultSlice(f.DefValue))
				return
			}
			_ = f.Value.Set(f.DefValue)
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(Root)
}

// decodeDefaultSlice inverts pflag's stringSliceValue.String(), which
// renders a slice default as "[" + csv-joined-elements + "]". Feeding
// that same bracketed form back into Set (rather than Replace) does
// not invert cleanly — see resetCommandFlagsNow — so callers that need
// the actual default elements go through this decoder instead.
func decodeDefaultSlice(defValue string) []string {
	inner := strings.TrimSuffix(strings.TrimPrefix(defValue, "["), "]")
	if inner == "" {
		return nil
	}
	rec, err := csv.NewReader(strings.NewReader(inner)).Read()
	if err != nil {
		return nil
	}
	return rec
}

// resetCommandFlags is resetCommandFlagsNow wired to a test: once now
// (undoing whatever an earlier test in the same binary left behind)
// and once more via t.Cleanup (so the next test starts clean
// regardless of run order, per -shuffle=on). Call it as the first
// line of any test that calls Root.Execute() or Root.SetArgs.
func resetCommandFlags(t *testing.T) {
	t.Helper()
	resetCommandFlagsNow()
	t.Cleanup(resetCommandFlagsNow)
}

// TestHelpInvocationDoesNotLeakIntoNextExecution is the regression
// guard for #283: running "<cmd> --help" must not silently short-
// circuit a later real invocation of the same command within the same
// test binary. Each case runs --help first, then a real invocation,
// and asserts the second one actually executed (rather than printing
// help again) by checking for output that only the real command path
// produces.
func TestHelpInvocationDoesNotLeakIntoNextExecution(t *testing.T) {
	cases := []struct {
		name     string
		helpArgs []string
		run      func(t *testing.T) (stdout string, err error)
	}{
		{
			// The exact scenario from PR #279's background: "scan git
			// --help" used to leave scanGitCmd's help flag stuck true.
			name:     "scan git",
			helpArgs: []string{"scan", "git", "--help"},
			run: func(t *testing.T) (string, error) {
				dir := t.TempDir()
				repo, err := gogit.PlainInit(dir, false)
				if err != nil {
					t.Fatalf("PlainInit: %v", err)
				}
				wt, err := repo.Worktree()
				if err != nil {
					t.Fatalf("Worktree: %v", err)
				}
				if err := writeFile(dir+"/clean.txt", "nothing secret here\n"); err != nil {
					t.Fatalf("seed fixture: %v", err)
				}
				if _, err := wt.Add("clean.txt"); err != nil {
					t.Fatalf("add: %v", err)
				}
				sig := &object.Signature{Name: "Test", Email: "test@example.com"}
				if _, err := wt.Commit("add-clean", &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
					t.Fatalf("commit: %v", err)
				}

				var out bytes.Buffer
				Root.SetOut(&out)
				Root.SetErr(&out)
				Root.SetArgs([]string{"scan", "--format", "json", "git", "--repo", dir})
				err = Root.Execute()
				return out.String(), err
			},
		},
		{
			// A second, unrelated command family: proves the fix is
			// general (walks the whole tree) rather than a one-off
			// patch for scanGitCmd alone.
			name:     "detectors list",
			helpArgs: []string{"detectors", "list", "--help"},
			run: func(t *testing.T) (string, error) {
				var out bytes.Buffer
				Root.SetOut(&out)
				Root.SetErr(&out)
				Root.SetArgs([]string{"detectors", "list", "--format", "names"})
				err := Root.Execute()
				return out.String(), err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetCommandFlags(t)

			var helpOut bytes.Buffer
			Root.SetOut(&helpOut)
			Root.SetErr(&helpOut)
			Root.SetArgs(tc.helpArgs)
			if err := Root.Execute(); err != nil {
				t.Fatalf("%v --help: %v", tc.helpArgs, err)
			}
			if !strings.Contains(helpOut.String(), "Usage:") {
				t.Fatalf("%v did not produce help output; got:\n%s", tc.helpArgs, helpOut.String())
			}

			// The convention for any test issuing more than one
			// Execute() call: reset again between calls, not just at
			// the top of the test. Without this line the assertions
			// below fail — the leftover --help state silently turns
			// the next call into another help print (#283).
			resetCommandFlagsNow()

			stdout, err := tc.run(t)
			if err != nil {
				t.Fatalf("real invocation after --help returned error: %v\noutput:\n%s", err, stdout)
			}
			if strings.Contains(stdout, "Usage:") {
				t.Fatalf("real invocation printed help instead of running; the --help flag leaked. output:\n%s", stdout)
			}
		})
	}
}
