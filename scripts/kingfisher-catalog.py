#!/usr/bin/env python3
"""Regenerate pkg/detectors/catalog/catalog_gen.go from kingfisher's rule
bundle: detection-only formats for every kingfisher rule pleno-dlp's native
detectors do not match (docs/kingfisher-parity.md partial/missing rows).

Usage: scripts/kingfisher-catalog.py <kingfisher-clone>
Then:  gofmt -w pkg/detectors; scripts/sync-detector-counts.sh;
       scripts/kingfisher-parity.py <kingfisher-clone>

Selection: every visible kingfisher rule whose synthesized fixtures no
native detector matches, measured with the catalog compiled out
(-tags kingfisher_nocatalog) by the same sampler as
scripts/kingfisher-parity.py. A rule for a provider pleno-dlp already has
attaches to that DetectorType (detectors.RegisterFormats); the rest attach
to a catalog host type from HOSTS below. New host
types are appended to the DetectorType enum and its String() switch between
the "kingfisher catalog hosts" markers, and listed in
docs/verify-coverage.md and pkg/detectors/verifycoverage (class per
HOST_CLASS). Patterns are kingfisher's (Apache-2.0; the Betterleaks import
is MIT), translated to RE2 where Rust-regex syntax differs ((?x) comments).
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
from re import _constants as C  # noqa: N812
from re import _parser as sp

# kingfisher rule-id prefix (after the namespace) -> host DetectorType for
# rules no native detector covers. Existing types are reused when the
# vendor already has one; the rest are new catalog host types.
HOSTS = {
    "1password-secret-key": "OnePasswordServiceAccount", "adafruit": "Adafruit",
    "age-secret-key": "AgeSecretKey", "alibaba": "AlibabaCloud", "asaas": "Asaas",
    "authress": "Authress", "azure-app-configuration": "AzureAppConfiguration",
    "azure-servicebus": "AzureServiceBus", "beamer": "Beamer", "bittrex": "Bittrex",
    "canva": "Canva", "clojars": "Clojars", "contentful": "Contentful",
    "coveralls": "Coveralls", "curl-auth": "CurlAuth", "defined-networking": "DefinedNetworking",
    "devin": "Devin", "docker-swarm": "DockerSwarm", "duffel": "Duffel", "ebay": "EBay",
    "endorlabs": "EndorLabs", "facebook": "Facebook", "finicity": "Finicity",
    "finnhub": "Finnhub", "flickr": "Flickr", "freemius": "Freemius",
    "freshbooks": "FreshBooks", "greptile": "Greptile", "infracost": "Infracost",
    "intra42": "Intra42", "kubernetes-secret-yaml": "KubernetesSecret", "kucoin": "KuCoin",
    "linkedin": "LinkedIn", "lob": "Lob", "mattermost": "Mattermost", "maxmind": "MaxMind",
    "microsoft-teams-webhook": "MicrosoftTeamsWebhook", "nuget-config-password": "NuGet",
    "nytimes": "NYTimes", "openshift": "OpenShift", "ovh": "OVHCloud",
    "polymarket": "Polymarket", "privateai": "PrivateAI", "rainforest-pay": "RainforestPay",
    "ramp": "Ramp", "rapidapi": "RapidAPI", "readme": "ReadMe", "scalingo": "Scalingo",
    "sendbird": "Sendbird", "settlemint": "SettleMint", "sidekiq": "Sidekiq",
    "tableau": "Tableau", "twitter": "Twitter", "typeform": "Typeform", "yandex": "Yandex",
    "zai": "ZAI", "codecatalystcredentials": "AWSCodeCatalyst",
    "codecommitcredentials": "AWSCodeCommit", "packagist": "Packagist",
}
# Corrections where the parity script's provider heuristic picks the wrong
# existing type for an uncovered rule.
TARGET = {
    "betterleaks.slack-webhook-url": "SlackWebhook",
    "betterleaks.slack-legacy-token": "SlackUserToken",
    "betterleaks.slack-session-token": "SlackUserToken",
    "betterleaks.slack-session-cookie": "SlackUserToken",
    "betterleaks.datadog-application-key": "DatadogAppKey",
}
# Host types reused from the existing enum (never re-declared).
REUSED = {"OnePasswordServiceAccount", "AlibabaCloud", "NuGet", "OVHCloud"}
# Reused enum members with no live registration (retired verifiers): the
# catalog registers them as detection-only hosts.
UNREGISTERED = {"AlibabaCloud"}
# verify-coverage class and rationale for new host types. Class b is
# unverified by design; class c is verifiable upstream but not implemented
# yet (tracked as a verify gap).
BY_DESIGN = {
    "AgeSecretKey": "offline age X25519 identity; no provider endpoint exists",
    "CurlAuth": "credential belongs to the arbitrary host on the same curl command line",
    "DockerSwarm": "self-hosted swarm manager, host not in chunk",
    "KubernetesSecret": "self-hosted cluster, API server not in chunk",
    "MicrosoftTeamsWebhook": "the only probe posts a message (destructive); no read-only endpoint",
    "OpenShift": "self-hosted cluster, API server not in chunk",
    "Tableau": "token is paired with a token name and a self-hosted/site-specific server",
    "AzureServiceBus": "SAS signing against the namespace in the connection string; no read-only bearer probe",
    "AzureAppConfiguration": "HMAC-SHA256 request signing against the store endpoint in the connection string",
}
# Rules deliberately not imported. generic-api-key is Betterleaks' catch-all
# assignment rule: on this repository alone it adds 257 findings that are
# English words and flag descriptions, while GenericHighEntropy already
# owns the generic class with stricter false-positive gates.
EXCLUDE = {"betterleaks.generic-api-key"}
BEGIN, END = "// BEGIN kingfisher catalog hosts (scripts/kingfisher-catalog.py)", "// END kingfisher catalog hosts"


def load_kp(repo):
    spec = importlib.util.spec_from_file_location("kp", os.path.join(repo, "scripts/kingfisher-parity.py"))
    kp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kp)
    return kp


def rule_meta(clone):
    """Per rule id: betterleaks secret group and entropy floor."""
    path = os.path.join(clone, "crates/kingfisher-rules/generated/builtin-rules.gz")
    import gzip
    text = gzip.open(path, "rt", encoding="utf-8", errors="replace").read()
    meta = {}
    for block in re.split(r"\n(?=- name: )", text):
        m = re.search(r"^  id: (\S+)", block, re.M)
        if not m:
            continue
        group = re.search(r"^  betterleaks_secret_group: (\d+)", block, re.M)
        ent = None
        em = re.search(r"value: entropy\n(?:.*\n){0,30}?\s+value: '?(\d+(?:\.\d+)?)'?", block)
        if em:
            ent = float(em.group(1))
        meta[m.group(1)] = (int(group.group(1)) if group else 0, ent)
    return meta


KEYWORDS = {  # prefilter keywords for rules kingfisher ships without any
    "betterleaks.voyageai-api-key": ["pa-", "al-"],
    "betterleaks.zai-api-key": ["."],
    "kingfisher.connection-string.password.odbc-braced": ["pwd", "password"],
}


def re2(p):
    """Translate Rust-regex syntax RE2 rejects: (?x) extended mode and
    repeat bounds above RE2's 1000 limit."""
    p = re.sub(r"\{(\d+),(\d{4,})\}", lambda m: "{%s,1000}" % m.group(1) if int(m.group(2)) > 1000 else m.group(0), p)
    m = re.match(r"\(\?([a-z]*)x([a-z]*)\)", p)
    if not m:
        return p
    flags = m.group(1) + m.group(2)
    return ("(?%s)" % flags if flags else "") + strip_x(p[m.end():])


def strip_x(p):
    """Drop unescaped whitespace and # comments outside character classes."""
    out, i, cls = [], 0, False
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            out.append(p[i:i + 2])
            i += 2
            continue
        if cls:
            if c == "]":
                cls = False
            out.append(c)
        elif c == "[":
            cls = True
            out.append(c)
        elif c == "#":
            while i < len(p) and p[i] != "\n":
                i += 1
            continue
        elif not c.isspace():
            out.append(c)
        i += 1
    return "".join(out)


def literal_keyword(pattern):
    """Longest literal run (>=3 chars) in the pattern, lower-cased, used as
    a prefilter keyword for rules that ship none."""
    try:
        tree = sp.parse(pattern.replace("(?<", "(?P<").replace("(?P<=", "(?<=").replace("(?P<!", "(?<!"))
    except Exception:  # noqa: BLE001
        return None
    best, cur = "", []

    def walk(t):
        nonlocal best, cur
        for op, av in t:
            if op == C.LITERAL:
                cur.append(chr(av))
                continue
            if len(cur) > len(best):
                best = "".join(cur)
            cur = []
            if op == C.SUBPATTERN:
                walk(av[-1])
                if len(cur) > len(best):
                    best = "".join(cur)
                cur = []
    walk(tree)
    if len(cur) > len(best):
        best = "".join(cur)
    best = best.strip()
    return best.lower() if len(best) >= 3 else None


def go_str(s):
    if "`" not in s:
        return "`" + s + "`"
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def go_bytes(b):
    """Go interpreted string literal for arbitrary bytes."""
    out = []
    for c in b:
        ch = chr(c)
        if ch in '"\\':
            out.append("\\" + ch)
        elif 0x20 <= c < 0x7f:
            out.append(ch)
        else:
            out.append("\\x%02x" % c)
    return '"' + "".join(out) + '"'


def host_for(rule_id):
    short = rule_id.split(".", 1)[1].split("/")[-1]
    for k in sorted(HOSTS, key=len, reverse=True):
        if short.startswith(k):
            return HOSTS[k]
    return None


def splice(path, body, indent=""):
    s = open(path).read()
    a, b = s.index(BEGIN), s.index(END)
    a = s.index("\n", a) + 1
    b = s.rindex("\n", 0, b) + 1
    open(path, "w").write(s[:a] + body + s[b:])


def main():
    clone = sys.argv[1]
    repo = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()
    kp = load_kp(repo)
    rules = {r["id"]: r for r in kp.load_rules(clone)}
    meta = rule_meta(clone)
    gen = os.path.join(repo, "pkg/detectors/catalog/catalog_gen.go")
    # Native coverage: scan the synthesized fixtures with the catalog
    # compiled out, and import only rules no native detector matches.
    native = json.loads(subprocess.run(
        ["go", "run", "-tags", "kingfisher_nocatalog", "./cmd/pleno-dlp", "detectors", "list", "--format", "json"],
        cwd=repo, capture_output=True, text=True, check=True).stdout)
    names = {re.sub("[^a-z0-9]", "", d["type"].lower()): d["type"] for d in native}
    hits = kp.scan(repo, list(rules.values()), tags="kingfisher_nocatalog")
    want = {}
    for rid, r in rules.items():
        if not r["visible"] or rid in EXCLUDE or kp.specific_hits(rid, hits):
            continue
        prov = TARGET.get(rid) or kp.provider(rid, names)
        if prov in kp.GENERIC and not kp.generic_rule(rid):
            prov = None
        want[rid] = prov or host_for(rid)
        if want[rid] is None:
            sys.exit(f"no host for uncovered rule {rid}; extend HOSTS")
    used = {t for t in want.values()} & set(HOSTS.values())
    new_hosts = sorted(h for h in used if h not in REUSED)
    hosts = sorted(new_hosts + [h for h in used if h in UNREGISTERED])
    lines = [
        "// Code generated by scripts/kingfisher-catalog.py; DO NOT EDIT.",
        "",
        "package catalog",
        "",
        'import "github.com/plenoai/pleno-dlp/pkg/detectors"',
        "",
        "// rules are kingfisher's detection formats (pin " + kp_pin(clone) + ") that",
        "// pleno-dlp's native detectors do not match. Patterns: mongodb/kingfisher",
        "// (Apache-2.0); the betterleaks.* rules are its Betterleaks import (MIT).",
        "var rules = []rule{",
    ]
    for rid in sorted(want):
        r = rules.get(rid)
        if r is None or not r["visible"] or rid in EXCLUDE:
            continue  # dropped upstream, or a hidden context-only rule
        group, ent = meta.get(rid, (0, None))
        kws = KEYWORDS.get(rid) or [k for k in r["kw"] if k.strip()]
        if not kws:
            lk = literal_keyword(r["pattern"])
            kws = [lk] if lk else []
        pat = re2(r["pattern"])
        validation = r["validation"]
        lines.append(
            f'\t{{ID: "{rid}", Type: detectors.{want[rid]}, Validation: "{validation}", '
            f'Group: {group}, MinEntropy: {ent or 0}, '
            f'Keywords: []string{{{", ".join(go_str(k) for k in kws)}}}, '
            f"Pattern: {go_str(pat)}" + (f", Path: {go_str(r['path'])}" if r["path"] else "") + "},")
    lines += ["}", "", "// hosts are catalog-only DetectorTypes: no native detector exists, so the",
              "// catalog registers a detection-only scanner for each.",
              "var hosts = []detectors.DetectorType{"]
    lines += [f"\tdetectors.{h}," for h in hosts]
    lines += ["}", ""]
    os.makedirs(os.path.dirname(gen), exist_ok=True)
    open(gen, "w").write("\n".join(lines))
    write_fixtures(kp, rules, want, os.path.join(repo, "pkg/detectors/catalog/fixtures_gen_test.go"), meta)

    det_go = os.path.join(repo, "pkg/detectors/detectors.go")
    reg_go = os.path.join(repo, "pkg/detectors/registry.go")
    declared = re.findall(r"^\t(\w+)$", open(det_go).read().split(BEGIN)[1].split(END)[0], re.M)
    order = declared + [h for h in new_hosts if h not in declared]  # append-only
    splice(det_go, "".join(f"\t{h}\n" for h in order))
    splice(reg_go, "".join(f'\tcase {h}:\n\t\treturn "{h}"\n' for h in order))

    validated = {}
    for rid, t in want.items():
        v = rules.get(rid, {}).get("validation", "-")
        if v != "-":
            validated.setdefault(t, set()).add(v)
    cls = {h: ("b" if h in BY_DESIGN else "c") for h in hosts}
    write_coverage(repo, cls, validated)
    print(f"{len(want)} rules, {len(hosts)} hosts ({len(new_hosts)} new)", file=sys.stderr)


def entropy(s):
    import math
    from collections import Counter
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0


def secret_of(kp, pattern, group, text):
    m = re.compile(kp.py_pattern(pattern)).search(text)
    if not m:
        return None
    if group > 0:
        return m.group(group)
    for g in range(1, (m.re.groups or 0) + 1):
        if m.group(g) is not None:
            return m.group(g)
    return m.group(0)


def write_fixtures(kp, rules, want, path, meta):
    """One synthesized positive per imported rule, stored reversed so the
    repository's own secret scanning (whose decoders would expand base64
    or hex and lose the file location) does not flag the test file."""
    out = ["// Code generated by scripts/kingfisher-catalog.py; DO NOT EDIT.", "",
           "package catalog", "", "// fixtures maps rule id to a reversed positive sample and, for",
           "// path-constrained rules, a source path satisfying the constraint.",
           "var fixtures = map[string]struct{ data, path string }{"]
    for rid in sorted(want):
        r = rules.get(rid)
        if r is None or not r["visible"] or rid in EXCLUDE:
            continue
        group, ent = meta.get(rid, (0, None))
        sample = None
        for seed in range(200):
            g = kp.Gen(1000 + seed, False, True)
            cand = g.sample(r["pattern"])
            sec = cand and secret_of(kp, r["pattern"], group, cand)
            if sec and entropy(sec) >= max(ent or 0, 1.5):
                sample = cand
                break
        if sample is None:
            continue
        # No trailing newline: RE2's $ is end-of-text, unlike Python's.
        text = "# " + " ".join(r["kw"][:3]) + "\n" + sample
        out.append(f'\t"{rid}": {{{go_bytes(text.encode()[::-1])}, "{"fixture" + kp.path_suffix(r["path"]) if r["path"] else ""}"}},')
    out += ["}", ""]
    open(path, "w").write("\n".join(out))


def kp_pin(clone):
    return subprocess.run(["git", "-C", clone, "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()


def write_coverage(repo, cls, validated):
    doc_p = os.path.join(repo, "docs/verify-coverage.md")
    doc = open(doc_p).read()
    rows = []
    for h in sorted(cls):
        if cls[h] == "b":
            why = BY_DESIGN[h] + " (kingfisher catalog host, detection-only)"
        else:
            via = ", ".join(sorted(validated.get(h, []))) or "none in kingfisher; provider API"
            why = f"kingfisher catalog host, detection-only; upstream verify path: kingfisher `{via}` validator (#898)"
        rows.append(f"| {h} | {cls[h]} | {why} |\n")
    a = doc.index("<!-- BEGIN kingfisher catalog hosts -->")
    b = doc.index("<!-- END kingfisher catalog hosts -->")
    a = doc.index("\n", a) + 1
    doc = doc[:a] + "| DetectorType | Class | Rationale |\n|---|---|---|\n" + "".join(rows) + doc[b:]
    a = doc.index("# BEGIN kingfisher catalog hosts")
    b = doc.index("# END kingfisher catalog hosts")
    a = doc.index("\n", a) + 1
    doc = doc[:a] + "".join(f"type={h} class={cls[h]}\n" for h in sorted(cls)) + doc[b:]
    open(doc_p, "w").write(doc)
    vc = os.path.join(repo, "pkg/detectors/verifycoverage/verifycoverage.go")
    names = {"b": "ClassUnverifiedByDesign", "c": "ClassVerifyGap"}
    splice(vc, "".join(f'\t"{h}": {names[cls[h]]},\n' for h in sorted(cls)))


if __name__ == "__main__":
    main()
