// Package kafka detects Kafka SASL/PLAIN credentials in client config
// blocks. Kafka clients carry credentials inside a `sasl.jaas.config`
// directive or as separate `sasl.username` / `sasl.password` properties.
//
//	sasl.username=alice
//	sasl.password=p4ss
//	bootstrap.servers=kafka.example.com:9093
//
// or:
//
//	sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule \
//	  required username="alice" password="p4ss";
//
// We capture the password as Raw and the (username, bootstrap) pair into
// ExtraData. RawV2 holds the username so reviewers can rotate the right
// principal.
//
// Verify is intentionally not performed. The Kafka broker is tenant-
// specific and probing it would emit SASL-failure log entries for the
// owning operator. So kafka surfaces unverified-by-design at SeverityHigh.
package kafka

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Property-style: `sasl.password=…`. Value runs to whitespace, quote, or
// line end.
var propPasswordRe = regexp.MustCompile(`(?i)sasl\.password\s*=\s*["']?([^\s"'<>;]+)`)
var propUsernameRe = regexp.MustCompile(`(?i)sasl\.username\s*=\s*["']?([^\s"'<>;]+)`)
var bootstrapRe = regexp.MustCompile(`(?i)bootstrap\.servers\s*=\s*["']?([^\s"'<>;]+)`)

// JAAS-style: `password="…"` and `username="…"` co-occurring with the
// PlainLoginModule directive. We require the directive nearby to keep
// this from firing on every JDBC connection string.
var jaasPasswordRe = regexp.MustCompile(`(?i)password\s*=\s*"([^"]+)"`)
var jaasUsernameRe = regexp.MustCompile(`(?i)username\s*=\s*"([^"]+)"`)
var jaasModuleRe = regexp.MustCompile(`(?i)PlainLoginModule|ScramLoginModule`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Kafka }

func (Scanner) Keywords() []string {
	return []string{"sasl.password", "sasl.jaas.config", "PlainLoginModule", "ScramLoginModule"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	out := make([]detectors.Result, 0, 2)
	seen := map[string]struct{}{}
	str := string(data)

	// Property-style results.
	for _, m := range propPasswordRe.FindAllStringSubmatch(str, -1) {
		password := m[1]
		if password == "" {
			continue
		}
		if _, dup := seen[password]; dup {
			continue
		}
		seen[password] = struct{}{}
		extra := map[string]string{"style": "property"}
		var username string
		if um := propUsernameRe.FindStringSubmatch(str); len(um) == 2 {
			username = um[1]
			extra["username"] = username
		}
		if bs := bootstrapRe.FindStringSubmatch(str); len(bs) == 2 {
			extra["bootstrap_servers"] = bs[1]
		}
		res := detectors.Result{
			DetectorType: detectors.Kafka,
			Raw:          []byte(password),
			Redacted:     redact(password),
			ExtraData:    extra,
			Severity:     detectors.SeverityHigh,
		}
		if username != "" {
			res.RawV2 = []byte(username)
		}
		out = append(out, res)
	}

	// JAAS-style — only when the LoginModule directive is present.
	if jaasModuleRe.FindStringIndex(str) != nil {
		for _, m := range jaasPasswordRe.FindAllStringSubmatch(str, -1) {
			password := m[1]
			if password == "" {
				continue
			}
			// Skip values that look like the property-style shape we already
			// emitted to avoid duplicates from mixed config dumps.
			if !strings.Contains(str, `password="`+password+`"`) {
				continue
			}
			if _, dup := seen[password]; dup {
				continue
			}
			seen[password] = struct{}{}
			extra := map[string]string{"style": "jaas"}
			var username string
			if um := jaasUsernameRe.FindStringSubmatch(str); len(um) == 2 {
				username = um[1]
				extra["username"] = username
			}
			if bs := bootstrapRe.FindStringSubmatch(str); len(bs) == 2 {
				extra["bootstrap_servers"] = bs[1]
			}
			res := detectors.Result{
				DetectorType: detectors.Kafka,
				Raw:          []byte(password),
				Redacted:     redact(password),
				ExtraData:    extra,
				Severity:     detectors.SeverityHigh,
			}
			if username != "" {
				res.RawV2 = []byte(username)
			}
			out = append(out, res)
		}
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func redact(t string) string {
	if len(t) <= 4 {
		return "..."
	}
	return t[:2] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
