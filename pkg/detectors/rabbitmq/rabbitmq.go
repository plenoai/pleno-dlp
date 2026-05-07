// Package rabbitmq detects RabbitMQ AMQP URIs that embed a password
// (`amqp://user:password@host` or `amqps://`). Password is the Raw secret;
// the full URI is RawV2.
//
// Verify is intentionally not performed. Probing the broker would publish
// a connection-attempt entry in the broker's log and risks impacting an
// unrelated production cluster. So rabbitmq surfaces unverified-by-design
// at SeverityHigh.
package rabbitmq

import (
	"context"
	"net/url"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var uriRe = regexp.MustCompile(`\b(amqps?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.RabbitMQ }

func (Scanner) Keywords() []string { return []string{"amqp://", "amqps://"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := uriRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		uri := string(m[1])
		password := string(m[2])
		if password == "" {
			continue
		}
		if _, dup := seen[uri]; dup {
			continue
		}
		seen[uri] = struct{}{}
		extra := map[string]string{}
		if u, err := url.Parse(uri); err == nil {
			if u.Host != "" {
				extra["host"] = u.Host
			}
			if u.User != nil {
				if name := u.User.Username(); name != "" {
					extra["user"] = name
				}
			}
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.RabbitMQ,
			Raw:          []byte(password),
			RawV2:        []byte(uri),
			Redacted:     redact(password),
			ExtraData:    extra,
			Severity:     detectors.SeverityHigh,
		})
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
