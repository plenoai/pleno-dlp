// Package all blank-imports every concrete detector so that their init()
// functions run and register themselves with pkg/detectors. Per ADR-0002, the
// CLI binary blank-imports this package; new detectors add one line here.
package all

import (
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/airtable"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/algolia"
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
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/openrouter"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/pagerduty"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/paypal"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/piicc"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/piiemail"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/piiiban"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/piissn"
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
	// batch 6 — wire-stable order, never reorder.
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
	// batch 7 — wire-stable order, never reorder.
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
	// batch 8 — wire-stable order, never reorder. Connection-string and
	// URL-embedded credentials, container-registry tokens, AWS S3 / GCS
	// presigned URLs, Azure SQL connection strings, kubeconfig, Adobe.io.
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
	// batch 9 — wire-stable order, never reorder. Enterprise SaaS leverage
	// tokens (project-management, alt-cloud GPU/IaaS, edge-Redis, DB platform,
	// auth, BaaS service-role).
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
	// batch 10 — wire-stable order, never reorder. Identity + IT-management
	// (OneLogin, JumpCloud), CI/CD (DroneCI, Harness), observability + cloud-
	// security (Lacework, Sysdig), localization (Lokalise), IaC platform
	// (Pulumi), docs/notes (Coda), email/comms (LoopsSo, Resend), mobile-app
	// platform (AppCenter), creator-platform OAuth (Twitch), secrets-manager
	// machine accounts (Bitwarden), and payments (Helcim).
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
	// batch 11 — wire-stable order, never reorder. Frontier-model admin
	// keys (Anthropic Console), AI infra (Pinecone, Weaviate, VoyageAI,
	// Fireworks, Cerebras), GitHub Apps installation tokens, JFrog
	// Artifactory, Pendo, PostHog, Sentry user tokens, Cloudflare R2
	// access-key + secret pair, Mapbox secret tokens, Railway, Telnyx.
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
	// batch 12 — wire-stable order, never reorder. Observability +
	// log-aggregator tokens, uptime monitoring, error-tracking, incident /
	// status, and CI/CD bearer tokens. Self-hosted (AWX, ConcourseCI,
	// TeamCity) and per-customer-host SaaS (SplunkHEC, ElasticCloud) are
	// unverified-by-design because the host isn't in the chunk.
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
	// batch 13 — wire-stable order, never reorder. Modern DBaaS platforms,
	// CI/CD bearer tokens distinct from existing GitLab PAT/Deploy shapes,
	// email/marketing (Constant Contact), telephony (Vonage), and
	// enterprise integration platforms (Workato, Aikido).
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
	// batch 14 — wire-stable order, never reorder. CDN/edge (Akamai,
	// Fastly), productivity / docs (Quip, Box, Zoho), payments / fintech
	// (Adyen, Wise, Razorpay, Mollie), telephony (MessageBird, Sinch),
	// S3-compatible object storage (Backblaze B2, Wasabi), identity
	// (Stytch), PaaS (Cloud66). Razorpay and Backblaze are paired
	// (key+secret); Stytch live, Razorpay live, and Mollie live surface
	// SeverityCritical when verified or matched.
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
)
