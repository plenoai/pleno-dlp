package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// fixture is one synthetic-corpus entry: exactly one format-valid
// synthetic credential of a known type, embedded in a few lines of
// realistic config context — mirrors docs/comparison.md §2's
// methodology ("one file per type ... embedded in 3-6 lines of
// realistic config context").
//
// Detector is the pleno-dlp DetectorType this fixture's secret is
// expected to trip. It is ground truth for pleno-dlp only — the
// harness (bench/harness) measures trufflehog/gitleaks recall live
// against the same files rather than hard-coding their expected
// outcome, because that expectation can only be validated by actually
// running the pinned binary. spec_test.go asserts the Detector claim
// against pleno-dlp's real engine, so a future detector regression (or
// an over-eager placeholder/FP filter swallowing a fixture) breaks
// `go test ./...`, not just a `make bench` run nobody's watching.
type fixture struct {
	Slug     string
	Detector detectors.DetectorType
	Render   func(rng *rand.Rand) string
}

// knownMisses documents current pleno-dlp false negatives, keyed by
// fixture slug — the "own losses" half of issue #298's requirement.
// spec_test.go asserts the miss instead of the hit for these slugs, so
// each note self-corrects: fix the detector and the test fails until
// the entry is removed here.
var knownMisses = map[string]string{
	"azure-storage-account-key": "pkg/detectors/azurestoragekey/azurestoragekey.go:37-39's connRe uses " +
		"`[^;]{0,200}` between the AccountName and AccountKey fields, which by construction cannot " +
		"cross the semicolon that always separates them in a real Azure connection string " +
		"(DefaultEndpointsProtocol=...;AccountName=...;AccountKey=...). The detector therefore never " +
		"fires on the one format Azure actually emits — discovered while building this fixture. Filed " +
		"as a follow-up for detector-engineer; not fixed in this bench-tooling change.",
}

// token repeatedly calls gen until the result survives
// engine.IsPlaceholder. Reusing pleno-dlp's own placeholder heuristic
// (rather than re-implementing "looks like a real secret" here) is
// what keeps the generator honest: known past bug (see CLAUDE.md) was
// a corpus containing malformed fixtures that quietly became fake
// competitor gaps. This is the mirror-image risk — a fixture the
// engine's own FP filter eats would quietly become a fake pleno-dlp
// loss — and it is checked mechanically instead of by hand.
func token(rng *rand.Rand, gen func(*rand.Rand) string) string {
	for i := 0; i < 200; i++ {
		t := gen(rng)
		if !engine.IsPlaceholder([]byte(t)) {
			return t
		}
	}
	panic("token: could not produce a non-placeholder value after 200 attempts")
}

const (
	lowerNum   = charsetLower + charsetDigit
	shopifyHex = charsetHex + charsetHexUpper
)

func jwtHS256(rng *rand.Rand) string {
	enc := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"sub": sample(rng, charsetDigit, 6), "iat": 1750000000})
	sig := sample(rng, charsetURLSafe, 24)
	return enc(header) + "." + enc(claims) + "." + sig
}

// pemBlock builds a "-----BEGIN <alg> PRIVATE KEY-----"..."-----END
// <alg> PRIVATE KEY-----" armor. pkg/detectors/privatekey's blockRe
// only anchors on the markers (body is `[\s\S]*?`), so the body content
// itself carries no format requirement beyond "present" — verified
// against the real detector in spec_test.go regardless.
func pemBlock(alg string) func(rng *rand.Rand) string {
	return func(rng *rand.Rand) string {
		return fmt.Sprintf(
			"-----BEGIN %s PRIVATE KEY-----\n%s\n%s\n-----END %s PRIVATE KEY-----",
			alg, sample(rng, charsetBase64, 64), sample(rng, charsetBase64, 64), alg,
		)
	}
}

// fixtures is the synthetic recall corpus. Slugs match docs/comparison.md
// §2's 50-type matrix where a pleno-dlp detector for that type exists in
// this repo today; see bench/README.md for the ones deliberately left out
// (generic-entropy-only or structurally out of scope for a fixed-format
// fixture) and why.
var fixtures = []fixture{
	{"aws-access-key-pair", detectors.AWS, func(r *rand.Rand) string {
		id := token(r, func(r *rand.Rand) string { return "AKIA" + sample(r, charsetUpperNum, 16) })
		secret := token(r, func(r *rand.Rand) string { return sample(r, charsetBase64, 40) })
		return fmt.Sprintf("aws_access_key_id     = %s\naws_secret_access_key = %s\n", id, secret)
	}},
	{"stripe-secret-key", detectors.Stripe, func(r *rand.Rand) string {
		prefixes := []string{"sk_live_", "sk_test_", "rk_live_"}
		prefix := prefixes[r.IntN(len(prefixes))]
		t := token(r, func(r *rand.Rand) string { return prefix + sample(r, charsetAlnum, 24) })
		return "STRIPE_SECRET_KEY=" + t + "\n"
	}},
	{"github-pat-classic", detectors.GitHub, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "ghp_" + sample(r, charsetAlnum, 36) })
		return "GITHUB_TOKEN=" + t + "\n"
	}},
	{"github-pat-fine-grained", detectors.GitHub, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "github_pat_" + sample(r, charsetAlnum+"_", 82) })
		return "GITHUB_TOKEN=" + t + "\n"
	}},
	{"gitlab-pat", detectors.GitLab, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "glpat-" + sample(r, charsetURLSafe, 20) })
		return "GITLAB_TOKEN=" + t + "\n"
	}},
	{"openai-api-key", detectors.OpenAI, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "sk-" + sample(r, charsetURLSafe, 24) })
		return "OPENAI_API_KEY=" + t + "\n"
	}},
	{"anthropic-api-key", detectors.Anthropic, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "sk-ant-" + sample(r, charsetURLSafe, 24) })
		return "ANTHROPIC_API_KEY=" + t + "\n"
	}},
	{"mailgun-api-key", detectors.Mailgun, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "key-" + sample(r, charsetHex, 32) })
		return "MAILGUN_API_KEY=" + t + "\n"
	}},
	{"npm-token", detectors.NPM, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "npm_" + sample(r, charsetAlnum, 36) })
		return "//registry.npmjs.org/:_authToken=" + t + "\n"
	}},
	{"sendgrid-api-key", detectors.SendGrid, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return "SG." + sample(r, charsetURLSafe, 22) + "." + sample(r, charsetURLSafe, 43)
		})
		return "SENDGRID_API_KEY=" + t + "\n"
	}},
	{"digitalocean-pat", detectors.DigitalOcean, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "dop_v1_" + sample(r, charsetHex, 64) })
		return "DO_TOKEN=" + t + "\n"
	}},
	{"dockerhub-pat", detectors.DockerHub, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "dckr_pat_" + sample(r, charsetURLSafe, 30) })
		return "DOCKERHUB_TOKEN=" + t + "\n"
	}},
	{"huggingface-token", detectors.HuggingFace, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "hf_" + sample(r, charsetAlnum, 34) })
		return "HF_TOKEN=" + t + "\n"
	}},
	{"notion-token", detectors.Notion, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "secret_" + sample(r, charsetAlnum, 43) })
		return "NOTION_TOKEN=" + t + "\n"
	}},
	{"linear-api-key", detectors.Linear, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "lin_api_" + sample(r, charsetAlnum, 40) })
		return "LINEAR_API_KEY=" + t + "\n"
	}},
	{"cloudflare-api-token", detectors.Cloudflare, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return sample(r, charsetURLSafe, 40) })
		return "CF_API_TOKEN=" + t + "\n"
	}},
	{"algolia-api-key", detectors.Algolia, func(r *rand.Rand) string {
		app := token(r, func(r *rand.Rand) string { return sample(r, charsetUpperNum, 10) })
		key := token(r, func(r *rand.Rand) string { return sample(r, charsetHex, 32) })
		return fmt.Sprintf("ALGOLIA_APP_ID=%s\nALGOLIA_ADMIN_KEY=%s\n", app, key)
	}},
	{"airtable-pat", detectors.Airtable, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return "pat" + sample(r, charsetAlnum, 14) + "." + sample(r, charsetHex, 64)
		})
		return "AIRTABLE_TOKEN=" + t + "\n"
	}},
	{"twilio-api-key", detectors.Twilio, func(r *rand.Rand) string {
		sid := token(r, func(r *rand.Rand) string { return "AC" + sample(r, charsetHex, 32) })
		tok := token(r, func(r *rand.Rand) string { return sample(r, charsetHex, 32) })
		return fmt.Sprintf("TWILIO_SID=%s\nTWILIO_TOKEN=%s\n", sid, tok)
	}},
	{"telegram-bot-token", detectors.Telegram, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return sample(r, charsetDigit, 9) + ":" + sample(r, charsetURLSafe, 34)
		})
		return "TELEGRAM_BOT_TOKEN=" + t + " # telegram bot\n"
	}},
	{"pagerduty-api-key", detectors.PagerDuty, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return sample(r, charsetURLSafe, 20) })
		return "# pagerduty integration\nPD_TOKEN=" + t + "\n"
	}},
	{"newrelic-license-key", detectors.NewRelic, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "NRRA-" + sample(r, charsetAlnum+"-", 42) })
		return "NEW_RELIC_LICENSE_KEY=" + t + "\n"
	}},
	{"vault-token", detectors.Vault, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "hvs." + sample(r, charsetURLSafe, 40) })
		return "VAULT_TOKEN=" + t + "\n"
	}},
	{"grafana-service-account-token", detectors.Grafana, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return "glsa_" + sample(r, charsetAlnum, 32) + "_" + sample(r, charsetHex, 8)
		})
		return "GRAFANA_TOKEN=" + t + "\n"
	}},
	{"netlify-access-token", detectors.Netlify, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "nfp_" + sample(r, charsetAlnum, 40) })
		return "NETLIFY_TOKEN=" + t + "\n"
	}},
	{"pypi-upload-token", detectors.PyPI, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "pypi-AgEIc" + sample(r, charsetURLSafe, 52) })
		return "PYPI_TOKEN=" + t + "\n"
	}},
	{"square-access-token", detectors.Square, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "EAAA" + sample(r, charsetURLSafe, 60) })
		return "SQUARE_TOKEN=" + t + "\n"
	}},
	{"shopify-access-token", detectors.Shopify, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "shpat_" + sample(r, shopifyHex, 32) })
		return "SHOPIFY_TOKEN=" + t + "\n"
	}},
	{"discord-bot-token", detectors.Discord, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return sample(r, charsetURLSafe, 26) + "." + sample(r, charsetURLSafe, 6) + "." + sample(r, charsetURLSafe, 30)
		})
		return "DISCORD_BOT_TOKEN=" + t + "\n"
	}},
	{"datadog-api-key", detectors.Datadog, func(r *rand.Rand) string {
		api := token(r, func(r *rand.Rand) string { return sample(r, charsetHex, 32) })
		app := token(r, func(r *rand.Rand) string { return sample(r, shopifyHex, 40) })
		return fmt.Sprintf("# datadog\nDD_API_KEY=%s\nDD_APP_KEY=%s\n", api, app)
	}},
	{"mailchimp-api-key", detectors.Mailchimp, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return sample(r, charsetHex, 32) + "-us" + sample(r, charsetDigit, 2)
		})
		return "MAILCHIMP_API_KEY=" + t + "\n"
	}},
	{"terraform-cloud", detectors.TerraformCloud, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return sample(r, charsetAlnum, 14) + ".atlasv1." + sample(r, charsetURLSafe, 62)
		})
		return "TFE_TOKEN=" + t + "\n"
	}},
	{"atlassian-api-token", detectors.Atlassian, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "ATATT3" + sample(r, charsetAlnum+"_=-", 70) })
		return "ATLASSIAN_API_TOKEN=" + t + "\n"
	}},
	{"sentry-dsn", detectors.Sentry, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return "https://" + sample(r, charsetHex, 32) + "@o12345.ingest.sentry.io/4504000"
		})
		return "SENTRY_DSN=" + t + "\n"
	}},
	{"asana-pat", detectors.Asana, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return "1/" + sample(r, charsetDigit, 16) + "/" + sample(r, charsetHex, 32)
		})
		return "ASANA_PAT=" + t + "\n"
	}},
	{"azure-storage-account-key", detectors.AzureStorageKey, func(r *rand.Rand) string {
		name := token(r, func(r *rand.Rand) string { return sample(r, lowerNum, 12) })
		key := token(r, func(r *rand.Rand) string { return sample(r, charsetBase64, 86) + "==" })
		// Real-world Azure connection-string shape (semicolon-delimited
		// key=value pairs — see the Azure Portal's own "Connection
		// string" field). See knownMisses: pleno-dlp's detector cannot
		// currently match this exact, standard shape.
		return fmt.Sprintf(
			"DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net\n",
			name, key,
		)
	}},
	{"slack-webhook-url", detectors.SlackWebhook, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return "https://hooks.slack.com/services/T" + sample(r, charsetUpperNum, 8) +
				"/B" + sample(r, charsetUpperNum, 8) + "/" + sample(r, charsetAlnum, 24)
		})
		return "SLACK_WEBHOOK_URL=" + t + "\n"
	}},
	{"slack-bot-token", detectors.SlackBotToken, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string {
			return "xoxb-" + sample(r, charsetDigit, 10) + "-" + sample(r, charsetDigit, 13) + "-" + sample(r, charsetAlnum, 26)
		})
		return "SLACK_BOT_TOKEN=" + t + "\n"
	}},
	{"rsa-private-key-pem", detectors.PrivateKeyPEM, pemBlock("RSA")},
	{"ec-private-key", detectors.PrivateKeyPEM, pemBlock("EC")},
	{"openssh-private-key", detectors.PrivateKeyPEM, pemBlock("OPENSSH")},
	{"pgp-private-key-block", detectors.PrivateKeyPEM, pemBlock("PGP")},
	{"jwt-hs256", detectors.JWT, func(r *rand.Rand) string {
		t := token(r, jwtHS256)
		return "Authorization: Bearer " + t + "\n"
	}},
	{"mongodb-srv-uri", detectors.MongoDB, func(r *rand.Rand) string {
		pass := token(r, func(r *rand.Rand) string { return sample(r, charsetAlnum, 16) })
		return "MONGO_URL=mongodb+srv://app:" + pass + "@cluster0.example.mongodb.net/app\n"
	}},
	{"postgres-uri-with-password", detectors.Postgres, func(r *rand.Rand) string {
		pass := token(r, func(r *rand.Rand) string { return sample(r, charsetAlnum, 16) })
		return "DATABASE_URL=postgres://app:" + pass + "@db.example.com:5432/app\n"
	}},
	{"mysql-conn-string", detectors.MySQL, func(r *rand.Rand) string {
		pass := token(r, func(r *rand.Rand) string { return sample(r, charsetAlnum, 16) })
		return "DATABASE_URL=mysql://root:" + pass + "@db.example.com:3306/app\n"
	}},
	{"redis-uri-with-password", detectors.Redis, func(r *rand.Rand) string {
		pass := token(r, func(r *rand.Rand) string { return sample(r, charsetAlnum, 16) })
		return "REDIS_URL=redis://default:" + pass + "@cache.example.com:6379/0\n"
	}},
	{"google-api-key", detectors.GCPAPIKey, func(r *rand.Rand) string {
		t := token(r, func(r *rand.Rand) string { return "AIza" + sample(r, charsetURLSafe, 35) })
		return "FIREBASE_KEY=" + t + "\n"
	}},
}
