package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors/aws"
)

// applySkipAWSAccounts merges --skip-aws-account and --skip-aws-account-file
// into the AWS detector's canary skip list. It always resets the list so a
// previous invocation in the same process cannot leak into this one.
func applySkipAWSAccounts(ids []string, file string) error {
	all := append([]string(nil), ids...)
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("--skip-aws-account-file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			for _, id := range strings.Split(line, ",") {
				all = append(all, strings.TrimSpace(id))
			}
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("--skip-aws-account-file: %w", err)
		}
	}
	if err := aws.SetSkipAccounts(all); err != nil {
		return fmt.Errorf("--skip-aws-account: %w", err)
	}
	return nil
}
