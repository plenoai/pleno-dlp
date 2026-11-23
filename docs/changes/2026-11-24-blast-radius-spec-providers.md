Owners: core-engineer, connector-engineer, qa

Extend blast-radius mapping (#848, epic #817) with the table-driven `pkg/blastradius/spec` mapper and 17 providers (OpenAI, Anthropic, Hugging Face, Buildkite, Harness, Gitea, Bitbucket, DigitalOcean, SendGrid, Stripe, CircleCI, HCP Terraform, Jira/Atlassian, Confluence, Pinecone, Asana, Fastly); follow Link/next/page/offset pagination up to 1000 items per listing (GitHub repositories and GitLab projects no longer stop at 100) without following cross-origin links; memoize mappings per credential hash and bound concurrent mappings per registry.
