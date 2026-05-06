# Examples

## `pleno_anonymize_bridge.py`

Adapter that exposes any `saas_scraper.Connector` as a
`pleno_pii_scanner.sources.base.SourceConnector` from
[pleno-anonymize](https://github.com/plenoai/pleno-anonymize). Demonstrates
that the two pipelines share a Document protocol — a saas-scraper
Document translates into a pii-scanner Document with a per-field copy
and no JSON round-trip.

### Run

```sh
uv pip install pleno-secret-scanner pleno-pii-scanner pleno-pii-scanner-recognizers
playwright install chromium

python -m examples.pleno_anonymize_bridge slack --workspace acme
```

Output is one line per fetched document: `<kind>:<path> (<chars> chars)`.

### Promotion path

When the bridge graduates from POC to a maintained package, port this
file to `pleno-anonymize/packages/pii-scanner-saas-scraper/` as a
workspace member, register it via the `pleno_pii_scanner.connectors`
entry point group, and add it to the workspace `pyproject.toml`.
