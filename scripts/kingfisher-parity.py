#!/usr/bin/env python3
"""Regenerate docs/kingfisher-parity.md: a machine-checked diff of the
credential types mongodb/kingfisher detects against pleno-dlp detectors.

Usage: scripts/kingfisher-parity.py <kingfisher-clone> [--out docs/kingfisher-parity.md]

Method (no network, deterministic for a given kingfisher pin and pleno-dlp tree):
  1. Read kingfisher's generated rule bundle
     (crates/kingfisher-rules/generated/builtin-rules.gz): the imported
     Betterleaks catalog, the selected Google Veles detectors, and the
     first-party kingfisher rules, each with its validation type.
  2. Synthesize positive fixtures from every rule's regex (three seeded
     variants: minimal, lowercase-preferring, randomized) plus the rule's
     keywords, and scan them with `pleno-dlp scan filesystem --no-verify`.
  3. Classify each rule:
       covered  - a provider-specific pleno-dlp detector fires on a fixture
                  (generic catch-alls do not count, except for kingfisher's
                  own generic / connection-string rules);
       partial  - no fixture fired, but pleno-dlp has a detector for the
                  provider (format, context, or checksum difference);
       missing  - no pleno-dlp detector for the credential type.
pkg/detectors/kingfisherparity_test.go checks the committed machine block
against the live registry.
"""
import argparse
import collections
import gzip
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from re import _constants as C  # noqa: N812
from re import _parser as sp

GENERIC = {"GenericHighEntropy", "APIKeyAssignment", "HardcodedPassword", "BasicAuth"}
# kingfisher rule-id prefix (after the namespace) -> pleno-dlp detector,
# for providers whose names differ or that the token heuristic misses.
# None marks a provider pleno-dlp has no detector for.
ALIAS = {
    "gcp-application-default-credentials": "GCPOAuth", "gcp-gemini-api": "GCPAPIKey",
    "gcp-service-account": "GCPServiceAccount", "gcp-api-key": "GCPAPIKey",
    "private-key": "PrivateKeyPEM", "generic-credential-uri": "GitCredentialsURL",
    "langchain-langsmith": "LangSmith", "sendinblue": "Brevo", "togetherai": "Together",
    "weights-and-biases": "Wandb", "cockroachlabs": "CockroachCloud", "artifactory": "JFrog",
    "bitbucketcredentials": "BitbucketCloud", "bitwardenoauth2access": "Bitwarden",
    "circleciproject": "CircleCI", "denopatorg": "DenoDeploy", "deno-account": "DenoDeploy",
    "herokuplatformkey": "Heroku", "postmanapikey": "Postman", "postmancollectiontoken": "Postman",
    "slackapp": "SlackBotToken", "grokxaiapikey": "XAI", "digitaloceanapikey": "DigitalOcean",
    "cloudflareapitoken": "Cloudflare", "hcpclientcredentials": "HashiCorpCloud",
    "npmjsaccesstoken": "NPM", "sendgrid": "SendGrid", "openrouter": "OpenRouter",
    "hashicorp-tf": "TerraformCloud", "connection-string": "HardcodedPassword",
    "mongodb-connection": "MongoDB", "new-relic": "NewRelic", "confluent": "Kafka",
    "sonar": "SonarQube", "azure-client-id": "AzureAD", "azure-tenant-id": "AzureAD",
    "kraken": "Kraken", "coinbase": "Coinbase", "okta": "Okta", "salesforce": "SalesforceRefresh",
    "snowflake": "Snowflake", "dropbox": "Dropbox", "twilio-api-key": "TwilioAPIKey",
    "1password-service-account": "OnePasswordServiceAccount", "canadian-digital-service-notify": "GCNotify",
    "checkout": "CheckoutCom", "datastax": "DataStaxAstra", "fal-api": "FalAI", "frameio": "FrameIO",
    "labelbox-api": "Labelbox", "lighton": "LightOn", "llama-cloud": "LlamaCloud", "crates-io": "CratesIO",
    "brave-search": "BraveSearch", "redirect-pizza": "RedirectPizza", "val-town": "ValTown",
    "polar-": "Polar", "datagov": "DataGov", "midtrans": "Midtrans", "nuget-api": "NuGet",
    "microsoft-teams-webhook": None, "docker-swarm": None, "kubernetes-secret-yaml": None,
    "nuget-config-password": None, "facebook": None, "twitter": None, "azure-servicebus": None,
    "azure-app-configuration": None, "alibaba": None, "yandex": None, "contentful": None,
    "nytimes": None, "kucoin": None, "bittrex": None, "finicity": None,
}
STOP = set(
    "api key keys token tokens secret secrets access pat client id oauth oauth2 auth personal "
    "service account private public app apikey credentials credential webhook url password user "
    "refresh v1 v2 legacy new old live test sandbox admin org project bot rw ro read write "
    "management deploy config level sdk server encryption signing identifier prod production".split()
)
ALNUM = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def load_rules(clone):
    path = os.path.join(clone, "crates/kingfisher-rules/generated/builtin-rules.gz")
    lines = gzip.open(path, "rt", encoding="utf-8", errors="replace").read().split("\n")
    rules, cur, i, inval = [], None, 0, False
    while i < len(lines):
        line = lines[i]
        if line.startswith("- name: "):
            cur = {"id": "", "validation": "-", "pattern": "", "kw": []}
            rules.append(cur)
            section = None
        elif cur is not None and re.match(r"^\S", line):
            cur = None
        elif cur is not None:
            m = re.match(r"^  (\w+):\s*(.*)", line)
            if m:
                key, val = m.groups()
                section = key
                if key == "id":
                    cur["id"] = val
                elif key == "pattern":
                    if val in ("|", "|-", ">", ">-"):
                        buf = []
                        i += 1
                        while i < len(lines) and (lines[i].startswith("    ") or lines[i] == ""):
                            buf.append(lines[i][4:])
                            i += 1
                        cur["pattern"] = "\n".join(buf).rstrip("\n")
                        continue
                    if val.startswith("'"):
                        val = val[1:-1].replace("''", "'")
                    elif val.startswith('"'):
                        val = json.loads(val)
                    cur["pattern"] = val
            elif section == "validation" and cur["validation"] == "-":
                m = re.match(r"^    type:\s*(\S+)", line)
                if m:
                    cur["validation"] = m.group(1)
            elif section == "keywords":
                m = re.match(r"^  - (.*)", line)
                if m:
                    cur["kw"].append(m.group(1).strip("'\""))
        i += 1
    return [r for r in rules if r["id"]]


def py_pattern(p):
    p = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", p).replace(r"\z", r"\Z")
    for k, v in {"[:alnum:]": "a-zA-Z0-9", "[:alpha:]": "a-zA-Z", "[:digit:]": "0-9",
                 "[:xdigit:]": "0-9a-fA-F", "[:upper:]": "A-Z", "[:lower:]": "a-z",
                 "[:space:]": " \\t", "[:word:]": "\\w", "[:punct:]": "!-/"}.items():
        p = p.replace(k, v)
    if re.search(r".\(\?i\)", p, re.S):
        p = "(?i)" + p.replace("(?i)", "")
    return p


class Gen:
    def __init__(self, seed, lower):
        self.rng, self.lower, self.rnd = random.Random(seed), lower, False

    def chars(self, items, neg):
        s = set()
        for op, av in items:
            if op == C.LITERAL:
                s.add(chr(av))
            elif op == C.RANGE:
                s.update(chr(c) for c in range(av[0], min(av[1], av[0] + 200) + 1))
            elif op == C.CATEGORY:
                s.update({C.CATEGORY_DIGIT: "0123456789", C.CATEGORY_WORD: ALNUM,
                          C.CATEGORY_SPACE: " ", C.CATEGORY_NOT_SPACE: ALNUM,
                          C.CATEGORY_NOT_DIGIT: "abcXYZ", C.CATEGORY_NOT_WORD: " "}.get(av, ""))
        if neg:
            return [c for c in ALNUM if c not in s] or ["Q"]
        return sorted(s)

    def gen(self, tree):
        out = []
        for op, av in tree:
            if op == C.LITERAL:
                out.append(chr(av))
            elif op == C.NOT_LITERAL:
                out.append("a" if chr(av) != "a" else "b")
            elif op == C.ANY:
                out.append("x")
            elif op == C.IN:
                neg = bool(av) and av[0][0] == C.NEGATE
                cs = self.chars(av[1:] if neg else av, neg)
                al = [c for c in cs if c.isalnum()]
                if self.lower:
                    cs = [c for c in cs if not (c.isupper() and c.lower() in cs)]
                    al = [c for c in al if not (c.isupper() and c.lower() in al)]
                pool = al if al and len(al) >= len(cs) // 3 else cs
                out.append(self.rng.choice(pool) if pool else "a")
            elif op in (C.MAX_REPEAT, C.MIN_REPEAT, C.POSSESSIVE_REPEAT):
                lo, hi, sub = av
                if hi == C.MAXREPEAT:
                    hi = lo + 12
                n = self.rng.randint(lo, min(hi, lo + 4)) if self.rnd else lo
                out.extend(self.gen(sub) for _ in range(n))
            elif op == C.SUBPATTERN:
                out.append(self.gen(av[-1]))
            elif op == C.BRANCH:
                out.append(self.gen(self.rng.choice(av[1]) if self.rnd else av[1][0]))
            elif op == C.ATOMIC_GROUP:
                out.append(self.gen(av))
            elif op in (C.AT, C.ASSERT, C.ASSERT_NOT, C.GROUPREF):
                pass
            else:
                out.append("a")
        return "".join(out)

    def sample(self, pattern):
        p = py_pattern(pattern)
        try:
            tree, rx = sp.parse(p), re.compile(p)
        except (re.error, Exception):  # noqa: BLE001 - unsupported syntax: no fixture
            return None
        for k in range(400):
            self.rnd = k > 0
            s = self.gen(tree)
            if rx.search(s):
                return s
        return None


def scan(repo, rules):
    with tempfile.TemporaryDirectory() as d:
        for variant, (seed, lower) in enumerate([(7, False), (1, True), (99, False)]):
            g = Gen(seed, lower)
            for r in rules:
                s = g.sample(r["pattern"])
                if s is None:
                    continue
                name = r["id"].replace("/", "_") + "@" + str(variant) + ".txt"
                with open(os.path.join(d, name), "w") as f:
                    f.write("# " + " ".join(r["kw"][:3]) + "\n" + s + "\n")
        out = subprocess.run(
            ["go", "run", "./cmd/pleno-dlp", "scan", "filesystem", d, "--no-verify", "--format", "jsonl"],
            cwd=repo, capture_output=True, text=True, check=False).stdout
    hits = collections.defaultdict(set)
    for line in out.splitlines():
        if line.startswith("{"):
            f = json.loads(line)
            hits[os.path.basename(f["path"]).split("@")[0]].add(f["detector"])
    return hits


def provider(rule_id, names):
    short = rule_id.split(".", 1)[1].split("/")[-1]
    for k in sorted(ALIAS, key=len, reverse=True):
        if short.startswith(k):
            return ALIAS[k]
    base = re.sub(r"\.\d+$", "", short)
    core = [t for t in re.split(r"[-_.]", base) if t and t not in STOP and not t.isdigit()]
    for n in range(len(core), 0, -1):
        k = "".join(core[:n])
        if len(k) < 3:
            continue
        if k in names:
            return names[k]
        if len(k) >= 5:
            for norm, real in sorted(names.items()):
                if norm.startswith(k):
                    return real
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kingfisher")
    ap.add_argument("--out", default="docs/kingfisher-parity.md")
    args = ap.parse_args()
    repo = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()
    pin = subprocess.run(["git", "-C", args.kingfisher, "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    listed = json.loads(subprocess.run(["go", "run", "./cmd/pleno-dlp", "detectors", "list", "--format", "json"],
                                       cwd=repo, capture_output=True, text=True, check=True).stdout)
    names = {re.sub("[^a-z0-9]", "", d["type"].lower()): d["type"] for d in listed}
    rules = load_rules(args.kingfisher)
    hits = scan(repo, rules)
    rows = []
    for r in rules:
        short = r["id"].split(".", 1)[1]
        prov = provider(r["id"], names)
        h = hits.get(r["id"].replace("/", "_"), set())
        if not (short.startswith("connection-string") or short == "generic-api-key"):
            h = h - GENERIC
            if prov in GENERIC:
                prov = None
        status = "covered" if h else ("partial" if prov else "missing")
        det = ",".join(sorted(h)) if h else (prov or "-")
        rows.append((r["id"], r["validation"], status, det))
    write(args.out, pin, rows)
    c = collections.Counter(s for _, _, s, _ in rows)
    print(f"{len(rows)} rules: {dict(c)}", file=sys.stderr)


def write(out, pin, rows):
    c = collections.Counter(s for _, _, s, _ in rows)
    cv = collections.Counter(s for _, v, s, _ in rows if v != "-")
    total, validated = len(rows), sum(1 for r in rows if r[1] != "-")
    lines = [
        "# kingfisher detector parity",
        "",
        "Machine-checked diff of the credential types",
        f"[mongodb/kingfisher](https://github.com/mongodb/kingfisher) (pin `{pin}`) detects",
        "against pleno-dlp detectors. Regenerate with",
        "`scripts/kingfisher-parity.py <kingfisher-clone>`; the method is in the",
        "script header. `pkg/detectors/kingfisherparity_test.go` fails when a",
        "detector named below is no longer registered or the summary drifts",
        "from the machine block. Epic #817.",
        "",
        "kingfisher's catalog is the imported Betterleaks configuration, the",
        "selected Google Veles detectors, and a few first-party rules. The",
        "`validation` column is kingfisher's live-validation type (`-` =",
        "detection only).",
        "",
        "Status:",
        "",
        "- **covered** — a provider-specific pleno-dlp detector fires on a",
        "  fixture synthesized from kingfisher's regex.",
        "- **partial** — pleno-dlp has a detector for the provider, but none",
        "  fired: a format variant, a stricter context or checksum rule, or a",
        "  fixture artefact. Each is a candidate for a format extension.",
        "- **missing** — no pleno-dlp detector for the credential type.",
        "",
        "## Summary",
        "",
        "| | covered | partial | missing | total |",
        "|---|---|---|---|---|",
        f"| all rules | {c['covered']} | {c['partial']} | {c['missing']} | {total} |",
        f"| with kingfisher validation | {cv['covered']} | {cv['partial']} | {cv['missing']} | {validated} |",
        "",
        "## Rules",
        "",
        "```parity-machine",
        f"kingfisher={pin}",
        f"total={total}",
        f"covered={c['covered']}",
        f"partial={c['partial']}",
        f"missing={c['missing']}",
    ]
    for rid, v, s, d in rows:
        lines.append(f"rule={rid} validation={v} status={s} detector={d}")
    lines += ["```", ""]
    with open(out, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
