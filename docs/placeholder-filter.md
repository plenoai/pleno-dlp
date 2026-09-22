# Placeholder filter (`IsPlaceholder`)

Design rationale for `pkg/engine/placeholder.go`, which recognises well-known
documentation / template literals so they don't get reported as leaked
secrets.

Two independent matching strategies are combined, chosen per-marker by how
safe a bare substring match is for that marker:

1. **Template-scaffolding markers** (`templateSubstrings` —
   `"your_token"`, `"your_key"`, `"your_secret"`, `"<token>"`, `"<secret>"`,
   `"<key>"`) match anywhere in the value via `bytes.Contains`. These only
   ever occur as deliberate scaffolding a human copy-pastes over
   (`"Bearer <TOKEN>"`, `"sk_live_YOUR_SECRET_HERE"`) — a real secret
   would never legitimately contain `"<token>"` or `"your_secret"` as a
   substring, so `Contains` carries no over-suppression risk.

2. **Word markers** (`wordMarkers` — `"example"`, `"placeholder"`,
   `"redacted"`) do NOT use `Contains`. A real credential can legitimately
   contain `"example"` as a substring (a key scoped to example.com
   infra, a generated password that happens to embed `"Example"`) — see
   issue #290, where FileZillaXML's correctly-extracted
   `"ExamplePas123"` was silently dropped by the old `Contains` check.
   Instead a word marker only trips `IsPlaceholder` when it dominates
   the value's shape: split the (lower-cased) value into runs of
   alphanumeric characters ("words", delimited by any non-alnum byte
   or the string boundary) and require the marker words to account
   for a strict majority — more than half — of the total alnum byte
   count. `"PLACEHOLDER"` (100% marker) and `"EXAMPLE_KEY"` (70% marker)
   trip it; `"ExamplePas123"` (no word boundary around `"example"` at
   all — it's a fragment of one continuous run) and `"Bearer REDACTED
   here"` (marker is 44% of the alnum content) do not.

A small number of specific, publicly-documented literals (the AWS SDK
docs' `AKIAIOSFODNN7EXAMPLE` access key id and its paired secret key) are
exact-matched instead of relying on either heuristic above: `"EXAMPLE"`
is a trailing fragment of one continuous alnum run there
(`AKIAIOSFODNN7EXAMPLE`), so it does not qualify as a standalone word
under rule 2, yet the literal is safe to always drop because it is a
fixed, universally-repeated docs placeholder that cannot correspond to
any real account.

Runs of a single repeated character (`X{8,}`, `0{10,}`) and a short list of
exact single-token placeholders (`dummy`, `test`, `foo`, `bar`, `password`,
`changeme`) are unaffected by any of the above — they were already
exact/structural matches, not substring matches, so they carried no
over-suppression risk to begin with.