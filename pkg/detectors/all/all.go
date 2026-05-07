// Package all blank-imports every concrete detector so that their init()
// functions run and register themselves with pkg/detectors. Per ADR-0002, the
// CLI binary blank-imports this package; new detectors add one line here.
package all

import (
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/anthropic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/aws"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cloudflare"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/datadog"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/digitalocean"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gcp"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/github"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gitlab"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hubspot"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/huggingface"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jwt"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailgun"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mongodbatlas"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/newrelic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/npm"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/openai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pagerduty"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/postman"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/privatekey"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pypi"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/salesforcerefresh"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sendgrid"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sentry"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/slack"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/stripe"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/terraformcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/twilio"
)
