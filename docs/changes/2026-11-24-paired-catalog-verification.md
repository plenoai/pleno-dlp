# Verify the paired-credential catalog hosts

Owners: detector-engineer, qa

Close the last nine class (c) rows (#956). Finicity (App-Key + partner ID), Freemius (signed `GET /v1/plugins/{id}.json` with plugin ID and public key), KuCoin (v2 signature with the passphrase partner; only `400003`/`400005` reject the candidate), LinkedIn (bogus-code probe; `invalid_client` rejects), and SettleMint (token sent only to an `https://*.settlemint.com` URL found next to it) now verify with partners resolved from the surrounding text and report a missing partner as indeterminate. Clojars (write-only deploy endpoint), Coveralls (public-repo 200s), Greptile (would forward an unrelated GitHub token), and PrivateAI (plan-bound hosts) move to class (b). Class (c) is empty: 643 verified, 80 unverified-by-design.
