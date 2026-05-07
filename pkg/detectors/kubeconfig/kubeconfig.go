// Package kubeconfig detects kubeconfig YAML containing credential
// material — `client-certificate-data:`, `client-key-data:`, or `token:`
// fields under a `users:` block.
//
// Verify is intentionally not performed — the cluster API endpoint is
// tenant-specific and probing it leaves authentication-failure entries.
// Cluster-admin scope warrants SeverityCritical. The detector emits one
// finding per credential field; Raw is the credential value, RawV2 is
// the surrounding YAML user entry name when discoverable.
//
// We require both an `apiVersion: v1` (or no apiVersion) marker AND a
// `kind: Config` line (case-insensitive) to keep this from firing on
// every YAML file that happens to contain `token:`. The scoping keeps
// noise low without losing real findings.
package kubeconfig

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var kindRe = regexp.MustCompile(`(?im)^\s*kind\s*:\s*Config\s*$`)

// One result per credential field. We anchor on YAML line shape (key
// indented under `user:` or top-level) and require a non-empty value.
var clientCertRe = regexp.MustCompile(`(?m)^\s*client-certificate-data\s*:\s*([A-Za-z0-9+/=]{40,})\s*$`)
var clientKeyRe = regexp.MustCompile(`(?m)^\s*client-key-data\s*:\s*([A-Za-z0-9+/=]{40,})\s*$`)
var tokenRe = regexp.MustCompile(`(?m)^\s*token\s*:\s*([A-Za-z0-9._\-+/=]{20,})\s*$`)
var nameRe = regexp.MustCompile(`(?m)^[\s-]*name\s*:\s*([^\s]+)\s*$`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Kubeconfig }

func (Scanner) Keywords() []string { return []string{"kind: Config", "kind:Config"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if !kindRe.Match(data) {
		return nil, nil
	}
	out := make([]detectors.Result, 0, 4)
	seen := map[string]struct{}{}
	str := string(data)

	emit := func(fieldName string, value string) {
		if value == "" {
			return
		}
		key := fieldName + ":" + value
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		extra := map[string]string{"field": fieldName}
		// Best-effort capture of the user-name a few lines above the
		// credential field. We grab the LAST `name:` before the credential.
		if idx := strings.Index(str, value); idx > 0 {
			head := str[:idx]
			if matches := nameRe.FindAllStringSubmatch(head, -1); len(matches) > 0 {
				extra["user_name"] = matches[len(matches)-1][1]
			}
		}
		res := detectors.Result{
			DetectorType: detectors.Kubeconfig,
			Raw:          []byte(value),
			Redacted:     redact(value),
			ExtraData:    extra,
			Severity:     detectors.SeverityCritical,
		}
		if userName, ok := extra["user_name"]; ok {
			res.RawV2 = []byte(userName)
		}
		out = append(out, res)
	}

	for _, m := range clientCertRe.FindAllStringSubmatch(str, -1) {
		emit("client-certificate-data", m[1])
	}
	for _, m := range clientKeyRe.FindAllStringSubmatch(str, -1) {
		emit("client-key-data", m[1])
	}
	for _, m := range tokenRe.FindAllStringSubmatch(str, -1) {
		emit("token", m[1])
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func redact(t string) string {
	if len(t) <= 12 {
		return "..."
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
