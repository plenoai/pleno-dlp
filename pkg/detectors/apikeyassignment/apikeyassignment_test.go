//go:build detector_unit

package apikeyassignment

import (
	"context"
	"testing"
)

func TestFromData_YAMLColonWithComment(t *testing.T) {
	data := []byte("authentication:\n" +
		"  client_key: 383c8164d4bdd95d8b1bfbf4f540d754 # Informative\n" +
		"  api_key: 3b6311afca5bd8aac647b316704e9c6d # Risk.\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "3b6311afca5bd8aac647b316704e9c6d" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_IniEqualsForm(t *testing.T) {
	data := []byte("api_key = 3b6311afca5bd8aac647b316704e9c6d\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
}

func TestFromData_HyphenAndBareVariants(t *testing.T) {
	cases := []string{
		"api-key: 3b6311afca5bd8aac647b316704e9c6d\n",
		"apikey: 3b6311afca5bd8aac647b316704e9c6d\n",
		"DO_API_KEY: 3b6311afca5bd8aac647b316704e9c6d\n",
	}
	for _, data := range cases {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte(data))
		if len(res) != 1 {
			t.Fatalf("expected 1 for %q, got %d: %+v", data, len(res), res)
		}
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"client_key is not api_key", "client_key: 383c8164d4bdd95d8b1bfbf4f540d754\n"},
		{"placeholder value", "api_key: changeme\n"},
		{"templated value", "api_key: ${API_KEY}\n"},
		{"too short", "api_key: ab\n"},
		{"unrelated key containing key substring", "ssh_key_path: \"~/.ssh/deploy.pem\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
			}
		})
	}
}
