package cmd

import (
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

func TestSaaSScopeDescriptorDistinguishesScopesAndDropsSecrets(t *testing.T) {
	a, err := saasScopeDescriptor("gitlab", connectors.Config{"group": "a", "token": "glpat-SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := saasScopeDescriptor("gitlab", connectors.Config{"group": "b", "token": "glpat-SECRET"})
	if string(a) == string(b) {
		t.Fatalf("scopes collide: %s", a)
	}
	c, _ := saasScopeDescriptor("gitlab", connectors.Config{"group": "a", "token": "other"})
	if string(a) != string(c) {
		t.Fatalf("token rotation changed scope: %s vs %s", a, c)
	}
	az, _ := saasScopeDescriptor("azure-blob", connectors.Config{
		"container_url": "https://u:p@acct.blob.core.windows.net/c?sv=x&sig=SAS",
		"sas_token":     "sig=SAS", "app_private_key": "PEM", "api_key": "K", "password": "P",
	})
	for _, bad := range []string{"SAS", "PEM", `"K"`, `"P"`, "u:p"} {
		if strings.Contains(string(az), bad) {
			t.Fatalf("descriptor leaks %q: %s", bad, az)
		}
	}
	if !strings.Contains(string(az), "acct.blob.core.windows.net/c") {
		t.Fatalf("scope lost container: %s", az)
	}
}
