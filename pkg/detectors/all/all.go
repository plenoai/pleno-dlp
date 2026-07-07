// Package all blank-imports every concrete detector for self-registration.
package all

import (
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/airtable"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/algolia"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/anonymize"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/anthropic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/asana"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/atlassian"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/auth0"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/aws"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/azuread"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bitbucketcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/brevo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/buildkite"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/circleci"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cloudflare"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cohere"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/confluence"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/datadog"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/digitalocean"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/discord"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/doppler"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dropbox"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/flyio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gcp"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/generic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/github"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gitlab"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/grafana"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/groq"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/heroku"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hubspot"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/huggingface"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/intercom"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jira"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jwt"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/launchdarkly"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/linear"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailchimp"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailgun"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mistral"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mixpanel"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mongodbatlas"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/netlify"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/newrelic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/notion"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/npm"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/okta"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/openai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/openaipf"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/openrouter"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pagerduty"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/paypal"
	// Legacy regex PII detectors were removed; ordinals stay pinned.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/plaid"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/postman"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/postmark"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/privatekey"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pypi"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/render"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/replicate"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/salesforcerefresh"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/segment"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sendgrid"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sentry"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/shodan"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/slack"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/snyk"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/spotify"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/square"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/stripe"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/telegram"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/terraformcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/together"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/twilio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vault"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vercel"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/virustotal"
	// batch 6 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/awssession"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/azuresas"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bitbucketserver"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bugsnag"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/codecov"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/figma"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gcpapikey"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gcpoauth"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gitlabdeploy"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/honeycomb"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/klaviyo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/rollbar"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sumologic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/tailscale"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/zoom"
	// batch 7 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/aliyun"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/azureapp"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/databricks"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/datadogapp"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dopplercli"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/freshdesk"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gcpidtoken"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hashicorpcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/launchdarklyrelay"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ngrok"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/opsgenie"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/snowflake"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/tencentcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/terraformcloudteam"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/zendesk"
	// batch 8 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/adobeio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/awss3presigned"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/azuresqlconn"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/basicauth"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dockerhub"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gcssignedurl"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ghcr"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kafka"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kubeconfig"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mongodb"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mysql"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/postgres"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/rabbitmq"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/redis"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/smtp"
	// batch 9 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/clerk"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/clickup"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gitter"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/launchnotes"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/linode"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/modal"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/monday"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/paperspace"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/planetscale"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/runpod"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/scaleway"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/supabase"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/trello"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/upstashredis"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vultr"
	// batch 10 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/appcenter"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bitwarden"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/coda"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/droneci"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/harness"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/helcim"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jumpcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lacework"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lokalise"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/loopsso"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/onelogin"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pulumi"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/resend"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sysdig"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/twitch"
	// batch 11 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/anthropicadmin"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cerebras"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cloudflarer2"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fireworks"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/githubapp"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jfrog"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mapbox"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pendo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pinecone"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/posthog"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/railway"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sentryuser"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/telnyx"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/voyageai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/weaviate"
	// batch 12 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/awx"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/concourseci"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/coralogix"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/elasticcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/honeybadger"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/loggly"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/logzio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pagertree"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pingdom"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/raygun"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/splunkhec"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/statuspage"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/teamcity"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/uptimerobot"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/victorops"
	// batch 13 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/aikidosecurity"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/aiven"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/argocd"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/clickhousecloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cockroachcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/constantcontact"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fauna"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gitlabpipeline"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/neon"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/spinnaker"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/tektonhub"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/tinybird"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vonage"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/workato"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/yugabytecloud"
	// batch 14 — append-only.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/adyen"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/akamai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/backblazeb2"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/box"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cloud66"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fastly"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/messagebird"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mollie"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/quip"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/razorpay"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sinch"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/stytch"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/wasabi"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/wise"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/zoho"
	// batch 15 — wire-stable order, never reorder. Identity/DevOps (AzureDevOps),
	// self-hosted CI / build (Jenkins, GoCD, Bamboo), productivity / workflow
	// (Smartsheet, Wrike, Productboard, Miro, Lucidchart), build artifacts
	// (SonatypeNexus), mobile / app distribution (AppStoreConnect, Bitrise,
	// Browserstack), generative AI (StabilityAI), network / security
	// (CiscoMeraki). Self-hosted Jenkins / GoCD / Bamboo / SonatypeNexus and
	// AppStoreConnect are unverified-by-design.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/appstoreconnect"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/azuredevops"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bamboo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bitrise"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/browserstack"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ciscomeraki"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gocd"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jenkins"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lucidchart"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/miro"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/productboard"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/smartsheet"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sonatypenexus"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/stabilityai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/wrike"
	// batch 16 — wire-stable order, never reorder. Identity/SSO (Webex,
	// PingIdentity), security tooling (Tenable, Rapid7, CrowdStrike, Wiz,
	// SonarQube), email/marketing (MailerLite, ActiveCampaign, Drip),
	// CDN/storage/media (BunnyCDN, Vimeo, Cloudinary), video infra (Mux),
	// webhooks (Hookdeck). Wiz / ActiveCampaign / PingIdentity unverified.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/activecampaign"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bunnycdn"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cloudinary"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/crowdstrike"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/drip"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hookdeck"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailerlite"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mux"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pingidentity"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/rapid7"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sonarqube"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/tenable"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vimeo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/webex"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/wiz"
	// batch 17 — wire-stable order, never reorder. Identity/SSO (WorkOS,
	// FrontEgg, Kinde, Hanko), CI/DevOps/artifacts (GitHubFineGrained,
	// AzureContainerRegistry, Quay, Replit), email/comms (PostmarkAccount,
	// Beehiiv), DNS/edge (NS1), generative AI (Perplexity, DeepInfra, XAI),
	// payments (GoCardless). Kinde / Hanko / AzureContainerRegistry are
	// unverified-by-default — they need per-tenant or per-registry hosts the
	// chunk doesn't carry.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/azurecr"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/beehiiv"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/deepinfra"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/frontegg"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/githubfinegrained"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gocardless"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hanko"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kinde"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ns1"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/perplexity"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/postmarkaccount"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/quay"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/replit"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/workos"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/xai"
	// batch 18 — payments / banking (mercurybank, lemonsqueezy, schematic, hyperline,
	// fattureincloud), AI infra (vercelaigateway), CI / DevOps (codefresh, earthly,
	// spacelift), database (couchbasecapella), comms / SaaS (slackusertoken,
	// pusherchannels, pumble), IaaS (hetzner), and registrar (gandi). Spacelift /
	// PusherChannels are unverified-by-default (per-account host / HMAC scheme
	// requires extra config not in chunk). SlackUserToken (xoxp-) is distinct from
	// SlackBotToken (xoxb-).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/codefresh"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/couchbasecapella"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/earthly"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fattureincloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gandi"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hetzner"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hyperline"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lemonsqueezy"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mercurybank"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pumble"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pusherchannels"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/schematic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/slackusertoken"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/spacelift"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vercelaigateway"
	// batch 19 — IaaS / cloud (ovhcloud, equinixmetal, civo, exoscale), CI /
	// DevOps (buddyci, semaphoreci, jenkinsx), AI / ML (assemblyai,
	// elevenlabs, deepgram), email / comms (front, crispchat, drift),
	// security / compliance (vanta), mobile push (onesignal). OVHCloud /
	// Exoscale / CrispChat / SemaphoreCI / JenkinsX are unverified-by-default
	// (HMAC-signed, paired-secret-only, or per-installation hosts).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/assemblyai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/buddyci"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/civo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/crispchat"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/deepgram"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/drift"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/elevenlabs"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/equinixmetal"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/exoscale"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/front"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jenkinsx"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/onesignal"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ovhcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/semaphoreci"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vanta"
	// batch 20 — mobile push (firebasecloudmessaging, apns, pushover,
	// branchio, pusherbeams), compliance (drata, secureframe, onetrust),
	// CRM (pipedrive, closecrm), DNS (dnsimple), AI (nvidiangc), error
	// tracking (airbrake), database (materialize), identity
	// (beyondidentity). APNs / PusherBeams / OneTrust / BeyondIdentity
	// are unverified-by-default (per-tenant hosts or paired secrets
	// missing from the chunk).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/airbrake"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/apns"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/beyondidentity"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/branchio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/closecrm"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dnsimple"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/drata"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/firebasecloudmessaging"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/materialize"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/nvidiangc"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/onetrust"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pipedrive"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pusherbeams"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pushover"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/secureframe"
	// batch 21 — CDN / IaaS (keycdn, leaseweb), email (mailtrap, getresponse,
	// postageapp), analytics (amplitude, fullstory, heap, hotjar, optimizely),
	// localization (transifex, crowdin), e-sign (docusign), vector DB (qdrant),
	// DBaaS (surrealdb). Amplitude / Leaseweb are paired key+secret detectors
	// using RawV2. DocuSign / Qdrant / SurrealDB are unverified-by-default
	// (per-tenant / per-cluster hosts requiring apiBase override).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/amplitude"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/crowdin"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/docusign"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fullstory"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/getresponse"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/heap"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hotjar"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/keycdn"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/leaseweb"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailtrap"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/optimizely"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/postageapp"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/qdrant"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/surrealdb"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/transifex"
	// batch 22 — wire-stable order, never reorder. AI/ML (nomic, jina, runway),
	// data (motherduck, dolthub), observability (betterstack, dynatrace,
	// appsignal, scoutapm), auth (descope), email/messaging (mandrill,
	// customerio, iterable), telephony (plivo), payments (paddle). CustomerIO,
	// Plivo and ScoutAPM are paired credential detectors using RawV2.
	// Dynatrace is unverified-by-default (per-tenant host requires apiBase
	// override).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/appsignal"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/betterstack"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/customerio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/descope"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dolthub"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dynatrace"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/iterable"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jina"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mandrill"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/motherduck"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/nomic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/paddle"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/plivo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/runway"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/scoutapm"
	// batch 23 — wire-stable order, never reorder. E-commerce / payments
	// (shopify, recurly, chargebee, fastspring, gumroad, snipcart), VCS / CI
	// (gitea, woodpecker, octopusdeploy), observability (squadcast, instana),
	// comms / messaging (courier, bandwidth, lark), and analytics / activity
	// (getstream). Shopify / Chargebee / Gitea / Woodpecker / OctopusDeploy /
	// Instana are unverified-by-default (per-shop / per-tenant / self-hosted
	// host required). Bandwidth / FastSpring / Lark / GetStream are
	// paired-credential detectors using RawV2; GetStream is unverified-by-design
	// (HMAC-only).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bandwidth"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/chargebee"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/courier"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fastspring"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/getstream"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gitea"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gumroad"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/instana"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lark"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/octopusdeploy"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/recurly"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/shopify"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/snipcart"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/squadcast"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/woodpecker"
	// batch 24 — wire-stable order, never reorder. Payments (Braintree paired
	// access_token shape, Dwolla key+secret pair, Klarna paired username+
	// password Basic auth), HR / recruiting (Lever, Greenhouse, Gusto, Deel,
	// Rippling), auth (PropelAuth Bearer), AI / ML / GPU infra (LambdaLabs,
	// Anyscale, SambaNova, Baseten), DBaaS (Turso), notifications (Knock
	// `sk_(test|live)_`). Braintree / Dwolla / Klarna use RawV2 for the paired
	// secret. Knock live-prefix surfaces SeverityCritical via DefaultSeverity.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/anyscale"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/baseten"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/braintree"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/deel"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dwolla"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/greenhouse"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gusto"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/klarna"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/knock"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lambdalabs"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lever"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/propelauth"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/rippling"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sambanova"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/turso"
	// batch 25 — wire-stable order, never reorder. Shipping / e-commerce
	// (shippo, easypost, taxjar, avalara), HR / payroll (bamboohr, paylocity),
	// AI / inference (deepseek, monsterapi, friendliai), observability / APM
	// (appdynamics, elasticapm, lightstep), email / comms (emailjs, mailjet),
	// database / IaaS (hasura). Avalara / Mailjet / EmailJS use RawV2 for the
	// paired secret. BambooHR / AppDynamics / ElasticAPM / Hasura / Paylocity
	// are unverified-by-default (per-tenant host required).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/appdynamics"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/avalara"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bamboohr"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/deepseek"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/easypost"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/elasticapm"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/emailjs"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/friendliai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hasura"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lightstep"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailjet"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/monsterapi"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/paylocity"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/shippo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/taxjar"
	// batch 26 — wire-stable order, never reorder. AI / inference (ai21labs,
	// octoai), identity / SSO (pingone, forgerock, keycloak), marketing
	// (marketo, eloqua, pardot), customer messaging (kustomer, freshchat),
	// IaaS (oraclecloud, ibmcloud), and comms / SMS (ringcentral, dialpad,
	// signalwire). PingOne / KeyCloak / Marketo / Eloqua / Pardot / RingCentral
	// / SignalWire use RawV2 for the paired secret. ForgeRock / KeyCloak /
	// Marketo / Eloqua / OracleCloud / SignalWire are unverified-by-default
	// (per-tenant / per-realm / per-region host required).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ai21labs"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dialpad"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/eloqua"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/forgerock"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/freshchat"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ibmcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/keycloak"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kustomer"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/marketo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/octoai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/oraclecloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pardot"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pingone"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ringcentral"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/signalwire"
	// batch 27 — wire-stable order, never reorder. Frontier-AI (writer),
	// storage / DBaaS (filebase, storj, mongodbrealm), DevOps / CI (cloudbees,
	// codeship, okteto), CRM / sales (freshsales, copper), reviews (trustpilot),
	// endpoint security (sentinelone), customer support (gladly, helpscout),
	// email validation (mailboxlayer, hunter). CloudBees / Filebase / Storj /
	// MongoDBRealm / Freshsales / SentinelOne / Gladly are unverified-by-default
	// (per-tenant / per-bucket / per-app / per-region host). Copper / HelpScout
	// use RawV2 for paired creds.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cloudbees"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/codeship"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/copper"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/filebase"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/freshsales"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gladly"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/helpscout"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hunter"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailboxlayer"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mongodbrealm"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/okteto"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sentinelone"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/storj"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/trustpilot"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/writer"
	// batch 28 — wire-stable order, never reorder. AI / inference (alephalpha,
	// inflection, characterai, hyperbolic, leptonai, novitaai), email validation
	// / lead-gen (kickbox, abstractapi, neverbounce, snov, apollo, lemlist),
	// identity (authentik), and blockchain explorers / RPC (etherscan, alchemy).
	// Snov / Lemlist use RawV2 for the paired secret. Authentik is unverified-
	// by-default (per-tenant host required).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/abstractapi"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/alchemy"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/alephalpha"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/apollo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/authentik"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/characterai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/etherscan"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hyperbolic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/inflection"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kickbox"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lemlist"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/leptonai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/neverbounce"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/novitaai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/snov"
	// batch 29 — wire-stable order, never reorder. Web3 / blockchain RPC +
	// APIs (infura, quicknode, moralis, blockfrost, helius, thegraph, opensea),
	// vector DB (milvus), webhook proxy (beeceptor, smee), identity (ory,
	// supertokens), feature flags / experimentation (statsig, growthbook,
	// devcycle). Smee / Supertokens / Milvus / QuickNode are unverified-
	// by-default (per-channel / per-deployment / per-cluster / per-endpoint
	// host required).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/beeceptor"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/blockfrost"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/devcycle"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/growthbook"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/helius"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/infura"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/milvus"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/moralis"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/opensea"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ory"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/quicknode"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/smee"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/statsig"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/supertokens"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/thegraph"
	// batch 30 — wire-stable order, never reorder. Realtime / streaming
	// (pubnub, livekit, agoraio, dailyco), search (meilisearch, typesense,
	// marqo), API gateway / webhook proxy (kong, webhookrelay, requestbin),
	// SEO / marketing (ahrefs, semrush, june), and enterprise (workday,
	// qualys). LiveKit / AgoraIO / Meilisearch / Typesense / Marqo /
	// RequestBin / Workday / Qualys are unverified-by-default
	// (per-deployment / per-host / per-tenant value required).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/agoraio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ahrefs"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dailyco"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/june"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kong"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/livekit"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/marqo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/meilisearch"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pubnub"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/qualys"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/requestbin"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/semrush"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/typesense"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/webhookrelay"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/workday"
	// batch 31 — wire-stable order, never reorder. AI / inference (nebius,
	// dashscope, modelscope, dify, lobehub), identity (fusionauth, casdoor),
	// DBaaS / search / DB cloud (edgedbcloud, prismadata, opensearchcloud,
	// chromacloud), web3 (biconomy), enterprise (sapariba, oraclenetsuite),
	// and CI (travisci). LobeHub / FusionAuth / Casdoor / EdgeDBCloud /
	// OpenSearchCloud / Biconomy / SAPAriba / OracleNetSuite are
	// unverified-by-default (per-deployment / per-tenant / per-account value
	// required).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/biconomy"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/casdoor"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/chromacloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dashscope"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dify"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/edgedbcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fusionauth"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lobehub"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/modelscope"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/nebius"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/opensearchcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/oraclenetsuite"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/prismadata"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sapariba"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/travisci"
	// batch 32 — wire-stable order, never reorder. AI / inference (watsonx),
	// DevOps / artifact (harbor), data integration (fivetran, airbyte),
	// exchanges (coinbase, bitfinex, kraken), sales / CRM (outreach, salesloft,
	// zoominfo, sproutsocial), identity (gigya), payments (moonpay), and Web3
	// RPC (nearrpc, polygonrpc). Harbor / Airbyte / NearRPC / PolygonRPC /
	// Gigya are unverified-by-default (per-deployment / per-tenant /
	// per-data-center / per-endpoint host required); Coinbase / Bitfinex /
	// Kraken ship unsigned-bearer verify (production HMAC path 401s,
	// surfacing unverified — mocks verify cleanly).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/airbyte"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bitfinex"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/coinbase"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fivetran"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gigya"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/harbor"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kraken"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/moonpay"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/nearrpc"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/outreach"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/polygonrpc"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/salesloft"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sproutsocial"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/watsonx"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/zoominfo"
	// batch 33 — wire-stable order, never reorder. Social-media scheduling
	// (buffer, hootsuite), Web3 identity (magiclabs), workflow / automation
	// (pipedream, make, n8n), accounting (sageintacct), enterprise CRM
	// (microsoftdynamics, gainsight), marketing automation (freshmarketer),
	// search infra (vespacloud), competitive intelligence (similarweb), and
	// security tooling (vectra, expel, beyondtrust). MicrosoftDynamics /
	// VespaCloud / Vectra / BeyondTrust / SageIntacct / N8N are
	// unverified-by-default (per-tenant / self-hosted host required).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/beyondtrust"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/buffer"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/expel"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/freshmarketer"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gainsight"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hootsuite"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/magiclabs"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/make"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/microsoftdynamics"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/n8n"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pipedream"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sageintacct"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/similarweb"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vectra"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vespacloud"
	// batch 34 — wire-stable order, never reorder. Cloud-AI / inference
	// (vertexai, rekaai, aihorde, ollamacloud, runwayml), customer-success
	// platforms (planhat, vitally, churnzero, totango, sendoso), payments
	// / fintech (paystack, flutterwave), security tooling (mandiant,
	// abnormalsec), marketing automation (ortto). VertexAI / Planhat /
	// Totango are unverified-by-default (per-project / per-tenant host
	// required); Mandiant carries paired key + secret-id via Raw/RawV2.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/abnormalsec"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/aihorde"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/churnzero"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/flutterwave"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mandiant"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ollamacloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/ortto"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/paystack"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/planhat"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/rekaai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/runwayml"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sendoso"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/totango"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vertexai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vitally"
	// batch 35 — wire-stable order, never reorder. KYC / identity verification
	// (persona, sumsub, onfido, jumio, trulioo), email validation (zerobounce,
	// mailersend), DevOps / observability (opslevel), mobile CI (codemagic),
	// browser-testing (lambdatest, saucelabs, browserless), LLM observability
	// / AI gateway (helicone, portkey, langfuse). Sumsub / Jumio / SauceLabs /
	// Langfuse / LambdaTest are paired-credential detectors using RawV2.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/browserless"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/codemagic"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/helicone"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jumio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lambdatest"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/langfuse"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailersend"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/onfido"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/opslevel"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/persona"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/portkey"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/saucelabs"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sumsub"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/trulioo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/zerobounce"
	// batch 36 — wire-stable order, never reorder. LLM observability /
	// experiment tracking (langsmith, wandb, cometml, neptuneai,
	// promptlayer, arizeai), compliance (hyperproof), e-commerce (etsy,
	// walmart, woocommerce), customer support / messaging (missiveapp,
	// livechat, helpcrunch), edge serverless (denodeploy), zero-trust
	// networking (twingate). WooCommerce / Walmart are paired-credential
	// (RawV2). Twingate / WooCommerce are unverified-by-default
	// (per-tenant / per-store host required).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/arizeai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/cometml"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/denodeploy"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/etsy"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/helpcrunch"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hyperproof"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/langsmith"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/livechat"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/missiveapp"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/neptuneai"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/promptlayer"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/twingate"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/walmart"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/wandb"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/woocommerce"
	// batch 37 — wire-stable order, never reorder. Data platforms
	// (dbtcloud), low-code / workflow (tray, retool), mobile build
	// (expo), KYC / identity (alloy, veriff, idnow), GRC / compliance
	// (auditboard), incident response / DORA (firehydrant, incidentio,
	// rootly, sleuth), email / SMS (sparkpost, sendpulse), e-commerce
	// (squarespace). Alloy / Veriff / SendPulse are paired-credential
	// (RawV2 carries the secret half).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/alloy"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/auditboard"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dbtcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/expo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/firehydrant"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/idnow"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/incidentio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/retool"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/rootly"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sendpulse"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sleuth"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sparkpost"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/squarespace"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/tray"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/veriff"
	// batch 38 — wire-stable order, never reorder. LLM ops / agent /
	// tracing (traceloop, klu, langflow, openpipe), LLM security
	// (lakera), KYC (footprint, vouched), e-commerce (magento,
	// bigcommerce, faire), customer chat (tidio), data platforms
	// (looker), translation (deepl), bug bounty (hackerone), networking
	// (zerotier). Magento / Looker / BigCommerce keyword-anchor
	// disambiguates broad token shapes; Faire / Vouched / Footprint use
	// distinctive prefixes; HackerOne uses paired-credential (RawV2).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bigcommerce"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/deepl"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/faire"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/footprint"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hackerone"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/klu"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/lakera"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/langflow"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/looker"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/magento"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/openpipe"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/tidio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/traceloop"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vouched"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/zerotier"
	// batch 39 — wire-stable order, never reorder. LLM ops / ML
	// monitoring (fiddler, evidently), fraud / KYC (sift, signifyd,
	// kount), bug bounty (intigriti, bugcrowd), vulnerability mgmt
	// (semgrep), workflow / orchestration (temporalcloud, prefectcloud,
	// dagstercloud), serverless (flymachines), storage (vercelblob),
	// BI (modeanalytics), document (pdfshift). Sift / Signifyd / Mode
	// use paired-credential (RawV2); VercelBlob uses `vercel_blob_rw_`
	// prefix; rest are keyword-anchored bearer tokens.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/bugcrowd"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/dagstercloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/evidently"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/fiddler"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/flymachines"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/intigriti"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kount"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/modeanalytics"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pdfshift"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/prefectcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/semgrep"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/sift"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/signifyd"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/temporalcloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/vercelblob"
	// batch 40 — wire-stable order, never reorder. This batch lands the
	// 600th detector. Fraud / risk (riskified, forter, socure), LLM ops
	// (agenta), customer support (kayako, customerly), eng analytics
	// (jellyfish), SOAR (swimlane), workflow (parabola), email
	// (mailmodo), DBaaS (neo4jaura), security testing (portswigger),
	// search (kagi), IoT (arduinocloud, particleio).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/agenta"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/arduinocloud"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/customerly"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/forter"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jellyfish"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kagi"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/kayako"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/mailmodo"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/neo4jaura"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/parabola"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/particleio"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/portswigger"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/riskified"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/socure"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/swimlane"
	// batch 41 — wire-stable order, never reorder. Cloud storage (azurestoragekey).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/azurestoragekey"
	// batch 43 — IaC/config-file hardcoded credential detectors.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/hardcodedpassword"
	// batch 44 — issue #175 batch 1: structured config-file,
	// filename/schema-keyed extractors (pgpass, netrc, git-credentials
	// URL userinfo, unix crypt password hashes, PHP config secrets).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/gitcredentialsurl"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/netrc"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pgpass"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/phpconfigsecret"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/unixcrypthash"
	// batch 45 — issue #175 batch 2: SFTP-client / deploy JSON+XML
	// config cluster (jsonconfigsecret, filezillaxml,
	// jetbrainswebservers, esmtprc, apikeyassignment, npmrcauth).
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/apikeyassignment"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/esmtprc"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/filezillaxml"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jetbrainswebservers"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/jsonconfigsecret"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/npmrcauth"
)
