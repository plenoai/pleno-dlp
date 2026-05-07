# pleno-dlp

Unified DLP scanner — secrets and PII over filesystem and SaaS content.
Detector interface is trufflehog-compatible (Go); SaaS sources flow
through [saas-retriever](https://github.com/plenoai/saas-retriever) on
the Python side.

## Harness: pleno-dlp

**Goal:** maintain and evolve the unified DLP scanner — Go binary
(filesystem-only) + Python package (SaaS via saas-retriever, secret +
PII backends).

**Trigger:** invoke the `secret-scanner-orchestrator` skill when a
request involves any of:
- adding or modifying detectors or sources
- engine, CLI, output-format, or CI changes
- detector / source / backend interface changes (high blast radius)
- PII backend integration with pleno-anonymize

Single-file greps and trivial questions should be answered directly
without invoking the orchestrator.

## Workflow rules

- All Go packages live in a single Go module rooted at this repo. New
  packages go under `pkg/<area>/<name>/` without their own `go.mod`
  (single-module configuration).
- Go tests must pass `go test ./... -race`. Race-detector failures block
  PRs.
- Python tests must pass `uv run --frozen pytest` and stay ruff + mypy
  strict-clean.
- Releases trigger exclusively by tag push:
  - `vX.Y.Z` → Go binary release via GoReleaser trusted publishing.
  - `py-vX.Y.Z` → Python package release to PyPI via trusted publishing.
- `main` push runs build + tests only — it does not publish (this is a
  CLI binary, not a service).
- Because this tool handles secret material, every new secret detector
  must either implement `Verify()` or be explicitly marked
  unverified-only. PII backends must mark findings with
  `finding_class="pii"` so downstream callers can route by class.

## Change history

| Date | Change | Target | Reason |
|------|--------|--------|--------|
| 2026-05-06 | Initial harness (5 agents, 5 skills) + Go scaffold | repo-wide | Spun up from pleno-anonymize as a reference |
| 2026-05-06 | Translated harness to English | `.claude/`, `CLAUDE.md` | Operator language preference |
| 2026-05-06 | MVP end-to-end (filesystem source + AWS/GitHub/Slack/OpenAI/Anthropic detectors + scan CLI + json/sarif/table output) | `pkg/`, `cmd/` | Make the scanner usable from the command line; 51 race-clean tests, 11/11 e2e checks |
| 2026-05-06 | Python package 0.2.0 consuming saas-scraper (native/trufflehog/gitleaks backends, json/sarif/table sinks, CLI) | `python/`, `.github/workflows/{test,release}-py.yml` | SaaS-source path; Go binary keeps filesystem scope. Tag pattern `py-vX.Y.Z` |
| 2026-05-06 | Python 0.4.0 — switch to saas-retriever (API-only, no Playwright) | `python/` | Org-wide GitHub support, no Chromium |
| 2026-05-07 | Rebrand `pleno-secret-scanner` → `pleno-dlp`; Python 0.5.0 with PII backend slot | repo-wide | Unified DLP scanner consolidating secret + PII scans; pleno-anonymize trims to PII model + API only |
| 2026-05-07 | saas-retriever 1.0.0 with all 7 connectors (github, gitlab, bitbucket, notion, confluence, jira, slack); pleno-dlp 0.6.0 bridge surfaces every kind via `--option k=v` | `python/`, saas-retriever | Org-wide SaaS coverage; CLI now addresses all v1 connector kinds |
| 2026-05-07 | Strip pleno-anonymize to PII filter API + Model only (28 `pii-scanner*` packages, `deploy/`, scanner ADR/solution notes deleted) | pleno-anonymize | Single-responsibility per repo: pleno-anonymize hosts the PII model + API; pleno-dlp owns scanning |
| 2026-05-07 | Detector batches 1–3 (37 trufflehog-compatible detectors), decoder pipeline (base64/percent/hex), archive walker (zip/tar/gzip), severity classification + custom-rule loader, SARIF Code Scanning compliance, --fail-on, git history source, filesystem --include/--exclude globs | `pkg/detectors/`, `pkg/decoder/`, `pkg/archive/`, `pkg/output/sarif.go`, `pkg/sources/git/`, `cmd/scan.go` | Production-ready depth: 42 detectors, severity gating, decoded variants, archive expansion |
| 2026-05-08 | Stdin source + allowlist mechanism + detector batch 4 (15 more → 57 total: jira, confluence, bitbucketcloud, square, paypal, plaid, discord, cohere, replicate, mistral, groq, intercom, openrouter, together, dropbox); CHANGELOG.md; v0.2.0 tag-push trusted publishing | `pkg/sources/stdin/`, `pkg/engine/allowlist.go`, `pkg/detectors/`, `CHANGELOG.md` | Production-ready breadth: 57 detectors, FP allowlist, pipe-to-scan UX, 429 race-clean tests across 71 packages |
| 2026-05-08 | Generic high-entropy detector + `detectors list` introspection + detector batches 5 & 6 (30 more secret detectors → 88 secrets: AzureAD, Telegram, Shodan, VirusTotal, Doppler, Vault, Algolia, Airtable, Grafana, LaunchDarkly, Auth0, Buildkite, CircleCI, Snyk, Spotify, AWSSession, AzureSAS, GCPOAuth, GCPAPIKey, BitbucketServer, GitLabDeploy, Codecov, Rollbar, Bugsnag, SumoLogic, Honeycomb, Tailscale, Figma, Zoom, Klaviyo) + 4 PII detectors (Email, US SSN, Credit Card, IBAN with `finding_class=pii`) + shell completions + v0.3.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go`, `cmd/`, `README.md`, `CHANGELOG.md` | True DLP: 92 total detectors, PII class on the Go side, 633 race-clean tests across 106 packages |
| 2026-05-08 | Per-host verify rate limiter (`pkg/verify`, `--verify-rps`) + CI integration recipes (.pre-commit-hooks.yaml, docs/recipes/ for GitHub Actions / GitLab CI / pre-commit / allowlist patterns) + detector batch 7 (15 more → 103 secrets total: AlibabaCloud, AzureApp, Databricks, DatadogAppKey, DopplerCLI, Freshdesk, GCPIDToken, HashiCorpCloud, LaunchDarklyRelay, Ngrok, Opsgenie, Snowflake, TencentCloud, TerraformCloudTeam, Zendesk) + v0.4.0 tag-push | `pkg/verify/`, `pkg/detectors/`, `docs/recipes/`, `.pre-commit-hooks.yaml` | Enterprise readiness: 107 detectors, rate-limited verify, drop-in CI adoption, 704 race-clean tests across 122 packages |
| 2026-05-08 | Detector batch 8 (15 connection-string + cloud-URL detectors → 118 secrets total: redis, postgres, mysql, mongodb, rabbitmq, kafka, basicauth, smtp, adobeio, dockerhub, ghcr, awss3presigned, gcssignedurl, azuresqlconn, kubeconfig) + engine concurrency benchmarks (BenchmarkScan_ColdPath, BenchmarkKeywordMatch) + v0.5.0 tag-push | `pkg/detectors/`, `pkg/engine/bench_test.go`, `pkg/output/sarif.go` | Enterprise depth: 122 detectors, connection-string awareness, tunable concurrency, 756 race-clean tests across 137 packages |
| 2026-05-08 | Detector batch 9 (15 SaaS + GPU/IaaS + DBaaS detectors → 133 secrets total: clickup, monday, trello, gitter, launchnotes, paperspace, runpod, modal, linode, vultr, scaleway, upstashredis, planetscale, clerk, supabase) + `--include-detectors` / `--exclude-detectors` filter flags + engine.Stats end-of-scan summary on stderr (chunks/bytes/findings/duration) + dedup stdin label fix + v0.6.0 tag-push | `pkg/detectors/`, `pkg/engine/{engine.go,dedup.go}`, `cmd/pleno-dlp/cmd/scan.go` | Production-ready scoping: 137 detectors, scan-scope flags, observable progress, correct stdin handling, 847 race-clean tests across 152 packages |
| 2026-05-08 | Detector batch 10 (15 enterprise IAM/CI/SaaS detectors → 148 secrets total: onelogin, jumpcloud, twitch, lacework, droneci, harness, sysdig, lokalise, pulumi, coda, loopsso, appcenter, bitwarden, resend, helcim) + v0.7.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go`, `CHANGELOG.md` | trufflehog parity continues: 152 detectors (148 secret + 4 PII), 963 race-clean tests across 167 packages |
| 2026-05-08 | Detector batch 11 (15 frontier-AI/AI-infra/observability detectors → 163 secrets total: anthropicadmin, pinecone, weaviate, voyageai, fireworks, cerebras, githubapp, jfrog, pendo, posthog, sentryuser, cloudflarer2, mapbox, railway, telnyx) + v0.8.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | trufflehog parity continues: 167 detectors (163 secret + 4 PII), 1068 race-clean tests across 182 packages |
| 2026-05-08 | Detector batch 12 (15 observability/CI detectors → 178 secrets total: splunkhec, elasticcloud, logzio, coralogix, loggly, uptimerobot, pingdom, honeybadger, raygun, statuspage, victorops, pagertree, awx, concourseci, teamcity) + v0.9.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | Enterprise observability/CI coverage: 182 detectors (178 secret + 4 PII), 1163 race-clean tests across 197 packages |
| 2026-05-08 | Detector batch 13 (15 DBaaS/CI/marketing/telephony detectors → 193 secrets total: aiven, yugabytecloud, cockroachcloud, fauna, tinybird, clickhousecloud, neon, gitlabpipeline, argocd, tektonhub, spinnaker, constantcontact, vonage, workato, aikidosecurity) + v0.10.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | DBaaS + CI parity push: 197 detectors (193 secret + 4 PII), 1263 race-clean tests across 212 packages |
| 2026-05-08 | Detector batch 14 (15 payments/CDN/SSO/comms detectors → 208 secrets total: akamai, fastly, quip, box, zoho, adyen, wise, razorpay, mollie, messagebird, sinch, backblazeb2, wasabi, stytch, cloud66) + engineRecordingSink race fix + v0.11.0 tag-push | `pkg/detectors/`, `pkg/engine/engine_test.go` | Payments + edge-CDN coverage: 212 detectors (208 secret + 4 PII), 1362 race-clean tests across 227 packages |
| 2026-05-08 | Detector batch 15 (15 IAM/CI/mobile/artifact-store detectors → 223 secrets total: azuredevops, jenkins, gocd, bamboo, smartsheet, wrike, productboard, miro, lucidchart, sonatypenexus, appstoreconnect, bitrise, browserstack, stabilityai, ciscomeraki) + v0.12.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | IAM + mobile + artifact coverage: 227 detectors (223 secret + 4 PII), 1467 race-clean tests across 242 packages |
| 2026-05-08 | Detector batch 16 (15 security/network/email/AI-infra detectors → 238 secrets total: webex, tenable, rapid7, crowdstrike, wiz, sonarqube, mailerlite, activecampaign, drip, bunnycdn, vimeo, cloudinary, pingidentity, mux, hookdeck) + v0.13.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | Security + email + media coverage: 242 detectors (238 secret + 4 PII), 1583 race-clean tests across 257 packages |
| 2026-05-08 | Detector batch 17 (15 auth/AI/payments detectors → 253 secrets total: workos, frontegg, kinde, hanko, githubfinegrained, azurecr, quay, replit, postmarkaccount, beehiiv, ns1, perplexity, deepinfra, xai, gocardless) + v0.14.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | Auth + frontier-AI + payments coverage: 257 detectors (253 secret + 4 PII), 1696 race-clean tests across 272 packages |
| 2026-05-08 | Detector batch 18 (15 payments/AI/IaaS/comms detectors → 268 secrets total: mercurybank, lemonsqueezy, schematic, hyperline, fattureincloud, vercelaigateway, gandi, codefresh, earthly, spacelift, couchbasecapella, slackusertoken, pusherchannels, hetzner, pumble) + v0.15.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | Banking + AI gateway + IaaS coverage: 272 detectors (268 secret + 4 PII), 1801 race-clean tests across 287 packages |
| 2026-05-08 | Detector batch 19 (15 IaaS/voice-AI/compliance/mobile-push detectors → 283 secrets total: ovhcloud, equinixmetal, civo, exoscale, buddyci, semaphoreci, jenkinsx, assemblyai, elevenlabs, deepgram, front, crispchat, drift, vanta, onesignal) + v0.16.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | Voice-AI + compliance + IaaS coverage: 287 detectors (283 secret + 4 PII), 1904 race-clean tests across 302 packages |
| 2026-05-08 | Detector batch 20 (15 mobile-push/compliance/CRM/identity detectors → 298 secrets total: firebasecloudmessaging, apns, pushover, branchio, pusherbeams, drata, secureframe, onetrust, pipedrive, close, dnsimple, nvidiangc, airbrake, materialize, beyondidentity) + v0.17.0 tag-push | `pkg/detectors/`, `pkg/output/sarif.go` | Mobile push + compliance + CRM coverage: 302 detectors (298 secret + 4 PII), 2008 race-clean tests across 317 packages |
