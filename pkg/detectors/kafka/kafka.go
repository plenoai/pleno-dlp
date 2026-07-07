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

// JAAS-style: `password="…"` and `username="…"` that live *inside* a
// LoginModule directive's clause. JAAS config is a single logical line
// terminated by ';', so we locate each (Plain|Scram)LoginModule directive
// and only accept password/username fields that fall within the clause
// (between the directive and the next ';', capped at jaasClauseWindow
// bytes). This excludes co-located but unrelated password="…" fields
// (JDBC, Spring datasource, other beans) sharing the same chunk.
var jaasPasswordRe = regexp.MustCompile(`(?i)password\s*=\s*"([^"]+)"`)
var jaasUsernameRe = regexp.MustCompile(`(?i)username\s*=\s*"([^"]+)"`)
var jaasModuleRe = regexp.MustCompile(`(?i)(?:Plain|Scram)LoginModule`)

// jaasClauseWindow bounds how far after a LoginModule directive we will
// still treat a password/username field as belonging to its clause when
// no ';' terminator is found in the chunk (truncated config dumps).
const jaasClauseWindow = 200

// jaasMinEntropy is the Shannon-entropy floor (bits/char) a JAAS password
// must clear to be emitted. Well-known defaults ("changeit") and templating
// tokens ("${KAFKA_PASSWORD}") are caught by the placeholder filter; this
// floor exists to drop trivially low-variety strings (e.g. "aaaa", "0000")
// while still admitting realistic short SASL passwords such as "s3cr3t".
const jaasMinEntropy = 2.0

// placeholderValues are well-known non-secret defaults we never emit.
var placeholderValues = map[string]struct{}{
	"changeme": {}, "changeit": {}, "password": {}, "passwd": {},
	"secret": {}, "redacted": {}, "example": {}, "yourpassword": {},
	"your_password": {}, "todo": {}, "xxx": {}, "xxxx": {},
}

// interpolationRe matches values that are purely a templating token, e.g.
// ${KAFKA_PASSWORD} or {{ kafka.password }}, so they are never emitted as
// live secrets.
var interpolationRe = regexp.MustCompile(`^\s*(?:\$\{[^}]*\}|\{\{[^}]*\}\})\s*$`)

// isPlaceholder reports whether v is a templating token or a well-known
// non-secret default.
func isPlaceholder(v string) bool {
	if interpolationRe.MatchString(v) {
		return true
	}
	_, ok := placeholderValues[strings.ToLower(strings.TrimSpace(v))]
	return ok
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Kafka }

func (Scanner) Keywords() []string {
	return []string{"sasl.password", "sasl.jaas.config", "PlainLoginModule", "ScramLoginModule"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	out := make([]detectors.Result, 0, 2)
	seen := map[string]struct{}{}
	str := string(data)

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

	// JAAS-style — scoped to each LoginModule directive's clause. For every
	// (Plain|Scram)LoginModule occurrence we carve out the clause [directive,
	// next ';') (bounded by jaasClauseWindow) and only accept password/
	// username fields whose match start lies inside that clause. This keeps
	// unrelated password="…" fields elsewhere in the chunk out of Kafka.
	for _, mod := range jaasModuleRe.FindAllStringIndex(str, -1) {
		clauseStart := mod[0]
		clauseEnd := len(str)
		if semi := strings.IndexByte(str[clauseStart:], ';'); semi >= 0 {
			clauseEnd = clauseStart + semi
		}
		if clauseEnd-clauseStart > jaasClauseWindow {
			clauseEnd = clauseStart + jaasClauseWindow
		}
		clause := str[clauseStart:clauseEnd]

		var username string
		if um := jaasUsernameRe.FindStringSubmatch(clause); len(um) == 2 {
			username = um[1]
		}

		for _, m := range jaasPasswordRe.FindAllStringSubmatch(clause, -1) {
			password := m[1]
			if password == "" {
				continue
			}
			if isPlaceholder(password) {
				continue
			}
			if !detectors.HasMinEntropy(password, jaasMinEntropy) {
				continue
			}
			if _, dup := seen[password]; dup {
				continue
			}
			seen[password] = struct{}{}
			extra := map[string]string{"style": "jaas"}
			if username != "" {
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
