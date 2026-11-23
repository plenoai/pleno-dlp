Owners: detector-engineer, qa

Add the `TwilioAPIKey` detector for Twilio API key SIDs (`SK` + 32 hex), paired with the nearest 32-character secret and verified provider-confirmed via `GET /2010-04-01/Accounts.json` with HTTP Basic auth, plus a context-required Revoker that deletes the key with `DELETE /2010-04-01/Accounts/{AC}/Keys/{SK}.json` using `PLENO_DLP_REVOKE_TWILIO_ACCOUNT_SID` / `PLENO_DLP_REVOKE_TWILIO_AUTH_TOKEN` (HTTP 404 stays unconfirmed). Add `scripts/sync-detector-counts.sh`, which rewrites every published detector count from the registry (#854).
