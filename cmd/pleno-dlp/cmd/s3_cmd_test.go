package cmd

import (
	"strings"
	"testing"
)

func TestS3CommandExposesRoleChainAndComparableObjectLimit(t *testing.T) {
	for _, name := range []string{"role-arn", "role-session-name"} {
		if scanS3Cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing --%s", name)
		}
	}
	maxSize := scanS3Cmd.Flags().Lookup("max-size")
	if maxSize == nil || !strings.Contains(maxSize.Usage, "250 MiB") || !strings.Contains(maxSize.Usage, "archives: 50 MiB") {
		t.Fatalf("--max-size help does not document object/archive limits: %#v", maxSize)
	}
}
