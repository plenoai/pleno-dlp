"""SARIF 2.1.0 sink for GitHub code-scanning ingestion.

Buffers all findings then writes one SARIF document. The schema follows
the OASIS SARIF 2.1.0 spec. Each unique rule_id becomes a `rules` entry;
each finding becomes a `results` entry pointing at the original document
URI (native_url) when available.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterable
from typing import IO, Any

from pleno_dlp.findings import Finding

_VERSION = "0.2.0"


class SarifSink:
    async def emit(self, findings: AsyncIterable[Finding], *, stream: IO[str]) -> int:
        collected: list[Finding] = []
        async for f in findings:
            collected.append(f)
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        for f in collected:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.rule_id},
                    "defaultConfiguration": {"level": "error" if f.verified else "warning"},
                }
            results.append(_result(f))
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pleno-dlp",
                            "version": _VERSION,
                            "informationUri": "https://github.com/plenoai/pleno-dlp",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        stream.write(json.dumps(sarif, ensure_ascii=False, indent=2))
        stream.write("\n")
        stream.flush()
        return len(collected)


def _result(f: Finding) -> dict[str, Any]:
    uri = f.native_url or f.path
    region: dict[str, Any] = {}
    if f.line is not None:
        region["startLine"] = f.line
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
        }
    }
    if region:
        location["physicalLocation"]["region"] = region
    return {
        "ruleId": f.rule_id,
        "level": "error" if f.verified else "warning",
        "message": {
            "text": f"{f.rule_id} ({f.backend}, verified={f.verified}): {f.redacted}"
        },
        "locations": [location],
        "properties": {
            "backend": f.backend,
            "verified": f.verified,
            "source_kind": f.source_kind,
            "source_id": f.source_id,
        },
    }
