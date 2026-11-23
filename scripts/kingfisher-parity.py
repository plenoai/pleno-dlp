#!/usr/bin/env python3
"""Regenerate docs/kingfisher-parity.md: a machine-checked diff of the
credential types mongodb/kingfisher detects against pleno-dlp detectors.

Usage:
  scripts/kingfisher-parity.py             regenerate from the pinned snapshot
  scripts/kingfisher-parity.py --check     exit 1 if the committed doc is stale
  scripts/kingfisher-parity.py --kingfisher <clone>
                                           re-pin: refresh the snapshot from a
                                           kingfisher clone, then regenerate

Method (no network, byte-for-byte deterministic for a given snapshot and
pleno-dlp tree; TestKingfisherParityRegenerates runs --check, so the doc
cannot be hand-edited, issue #962):
  1. Read kingfisher's rules from scripts/testdata/kingfisher-rules.json,
     a pinned snapshot parsed from kingfisher's generated rule bundle
     (crates/kingfisher-rules/generated/builtin-rules.gz): the imported
     Betterleaks catalog, the selected Google Veles detectors, and the
     first-party kingfisher rules, each with its validation type.
  2. Synthesize positive fixtures from every rule's regex (six seeded
     variants: minimal, lowercase-preferring, and randomized ones whose
     high-entropy draws survive kingfisher's own entropy filter) plus the rule's
     keywords, recompute CRC32 checksum suffixes of GitHub/npm-style
     30+6 tokens (pleno-dlp rejects a bad checksum, #949), and scan them with `pleno-dlp scan filesystem --no-verify`.
  3. Classify each rule:
       covered  - a provider-specific pleno-dlp detector fires on a fixture
                  (generic catch-alls do not count, except for kingfisher's
                  own generic / connection-string rules);
       partial  - no fixture fired, but pleno-dlp has a detector for the
                  provider (format, context, or checksum difference);
       missing  - no pleno-dlp detector for the credential type;
       context  - kingfisher hides the rule (visible: false): an identifier,
                  host, or URL that only feeds another rule's validation and
                  is never reported, so it is not a detection gap.
  4. Record how pleno-dlp verifies each rule: the pkg/detectors/catalog
     check kind (scripts/kingfisher-checks), else "native" when a credited
     detector implements Verify, else "-".
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
import zlib
from re import _constants as C  # noqa: N812
from re import _parser as sp

SNAPSHOT = "scripts/testdata/kingfisher-rules.json"
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
# (seed, lowercase-preferring, randomized from the first draw). The
# randomized variants matter: kingfisher's Betterleaks filters reject
# low-entropy candidates (min entropy 3.5), so a minimal fixture such as
# "xoxb-0000000000-0000000000" is not a token kingfisher would report
# either, and pleno-dlp's entropy gates reject it for the same reason.
VARIANTS = [(7, False, False), (1, True, False), (99, False, False),
            (5, False, True), (13, False, True), (21, True, True)]


def load_rules(clone):
    path = os.path.join(clone, "crates/kingfisher-rules/generated/builtin-rules.gz")
    lines = gzip.open(path, "rt", encoding="utf-8", errors="replace").read().split("\n")
    rules, cur, i, inval = [], None, 0, False
    while i < len(lines):
        line = lines[i]
        if line.startswith("- name: "):
            cur = {"id": "", "validation": "-", "pattern": "", "kw": [], "visible": True, "path": ""}
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
                elif key == "path":
                    if val.startswith("'"):
                        val = val[1:-1].replace("''", "'")
                    elif val.startswith('"'):
                        val = json.loads(val)
                    cur["path"] = val
                elif key == "visible":
                    cur["visible"] = val.strip().lower() != "false"
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
    def __init__(self, seed, lower, always_rnd=False):
        self.rng, self.lower, self.rnd = random.Random(seed), lower, False
        self.always_rnd = always_rnd
        # After half the draws fail, fillers ('.', [\s\S]) emit a space so
        # a word boundary between a keyword and the secret can hold.
        self.spacey = False

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
            return [c for c in ALNUM if c not in s] or [c for c in " ;\n" if c not in s] or ["Q"]
        return sorted(s)

    def gen(self, tree):
        out = []
        for op, av in tree:
            if op == C.LITERAL:
                out.append(chr(av))
            elif op == C.NOT_LITERAL:
                out.append("a" if chr(av) != "a" else "b")
            elif op == C.ANY:
                out.append(" " if self.spacey else self.rng.choice(ALNUM) if self.always_rnd else "x")
            elif op == C.IN:
                neg = bool(av) and av[0][0] == C.NEGATE
                cs = self.chars(av[1:] if neg else av, neg)
                al = [c for c in cs if c.isalnum()]
                if self.lower:
                    cs = [c for c in cs if not (c.isupper() and c.lower() in cs)]
                    al = [c for c in al if not (c.isupper() and c.lower() in al)]
                pool = al if al and len(al) >= len(cs) // 3 else cs
                if self.spacey and " " in cs:
                    pool = [" "]
                out.append(self.rng.choice(pool) if pool else "a")
            elif op in (C.MAX_REPEAT, C.MIN_REPEAT, C.POSSESSIVE_REPEAT):
                lo, hi, sub = av
                if hi == C.MAXREPEAT:
                    hi = lo + 12
                if self.always_rnd:  # longer draws: higher entropy
                    n = self.rng.randint(min(hi, lo + 8), min(hi, lo + 24))
                else:
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
            self.rnd = self.always_rnd or k > 0
            self.spacey = k >= 200
            s = self.gen(tree)
            if rx.search(s):
                return s
        return None


B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
CHECKSUM_TOKEN = re.compile(r"\b(gh[pousr]|npm)_([A-Za-z0-9]{30})[A-Za-z0-9]{6}(?![A-Za-z0-9])")


def crc32_base62(s):
    """Mirror of detectors.CRC32Base62."""
    v, out = zlib.crc32(s.encode()), ""
    for _ in range(6):
        out, v = B62[v % 62] + out, v // 62
    return out


def fix_checksums(s):
    """Give checksum-suffixed token shapes a valid CRC32 suffix: the
    providers only issue such tokens, and pleno-dlp rejects the rest."""
    return CHECKSUM_TOKEN.sub(lambda m: f"{m[1]}_{m[2]}{crc32_base62(m[2])}", s)


# File-name suffixes satisfying kingfisher's path-constrained rules.
PATH_SUFFIX = [("php", ".php"), ("tf|hcl", ".tf"), ("ya?ml", ".yaml"), ("nuget", ".nuget.config"),
               ("bitwarden", "/bitwarden-cli/data.json"), ("_history", "_history")]


def path_suffix(path_re):
    if not path_re:
        return ".txt"
    for key, suffix in PATH_SUFFIX:
        if key in path_re:
            return suffix
    sys.exit(f"no fixture file name for path constraint {path_re!r}; extend PATH_SUFFIX")


def scan(repo, rules, tags=None):
    with tempfile.TemporaryDirectory() as d:
        for variant, (seed, lower, rnd) in enumerate(VARIANTS):
            g = Gen(seed, lower, rnd)
            for r in rules:
                s = g.sample(r["pattern"])
                if s is None:
                    continue
                s = fix_checksums(s)
                name = r["id"].replace("/", "_") + "@" + str(variant) + path_suffix(r["path"])
                os.makedirs(os.path.dirname(os.path.join(d, name)), exist_ok=True)
                with open(os.path.join(d, name), "w") as f:
                    f.write("# " + " ".join(r["kw"][:3]) + "\n" + s + "\n")
        proc = subprocess.run(
            ["go", "run"] + (["-tags", tags] if tags else []) +
            ["./cmd/pleno-dlp", "scan", "filesystem", d, "--no-verify", "--format", "jsonl"],
            cwd=repo, capture_output=True, text=True, check=False)
    if proc.returncode != 0 and not proc.stdout.strip():
        sys.exit(f"pleno-dlp scan failed ({proc.returncode}): {proc.stderr[-2000:]}")
    hits = collections.defaultdict(set)
    for line in proc.stdout.splitlines():
        if line.startswith("{"):
            f = json.loads(line)
            part = next(p for p in f["path"].split(os.sep) if "@" in p)
            hits[part.split("@")[0]].add(f["detector"])
    return hits


def generic_rule(rule_id):
    """kingfisher's own generic rules, which generic detectors may cover."""
    short = rule_id.split(".", 1)[1]
    return short.startswith("connection-string") or short == "generic-api-key"


def specific_hits(rule_id, hits):
    h = hits.get(rule_id.replace("/", "_"), set())
    return h if generic_rule(rule_id) else h - GENERIC


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
    ap.add_argument("--kingfisher", help="kingfisher clone to re-pin the snapshot from")
    ap.add_argument("--out", default="docs/kingfisher-parity.md")
    ap.add_argument("--check", action="store_true", help="fail if --out differs from a fresh generation")
    args = ap.parse_args()
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    snap_path = os.path.join(repo, SNAPSHOT)
    if args.kingfisher:
        if args.check:
            sys.exit("--check regenerates from the committed snapshot; drop --kingfisher")
        pin = subprocess.run(["git", "-C", args.kingfisher, "rev-parse", "--short=7", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        with open(snap_path, "w") as f:
            json.dump({"kingfisher": pin, "rules": load_rules(args.kingfisher)}, f, indent=1, sort_keys=True)
            f.write("\n")
    with open(snap_path) as f:
        snap = json.load(f)
    pin, rules = snap["kingfisher"], snap["rules"]
    listed = json.loads(subprocess.run(["go", "run", "./cmd/pleno-dlp", "detectors", "list", "--format", "json"],
                                       cwd=repo, capture_output=True, text=True, check=True).stdout)
    names = {re.sub("[^a-z0-9]", "", d["type"].lower()): d["type"] for d in listed}
    verifies = {d["type"] for d in listed if d.get("verifies")}
    checks = json.loads(subprocess.run(["go", "run", "./scripts/kingfisher-checks"],
                                       cwd=repo, capture_output=True, text=True, check=True).stdout)
    hits = scan(repo, rules)
    rows = []
    for r in rules:
        prov = provider(r["id"], names)
        h = specific_hits(r["id"], hits)
        if not generic_rule(r["id"]):
            if prov in GENERIC:
                prov = None
        if not r["visible"]:
            status = "context"
        else:
            status = "covered" if h else ("partial" if prov else "missing")
        det = ",".join(sorted(h)) if h else (prov or "-")
        if status == "context" and not h:
            det = "-"
        if r["id"] in checks:
            ver = checks[r["id"]]
        elif status == "covered" and any(x in verifies for x in det.split(",")):
            ver = "native"
        else:
            ver = "-"
        rows.append((r["id"], r["validation"], status, det, ver))
    text = render(pin, rows)
    out = os.path.join(repo, args.out) if not os.path.isabs(args.out) else args.out
    if args.check:
        with open(out) as f:
            if f.read() != text:
                sys.exit(f"{args.out} is stale or hand-edited; run scripts/kingfisher-parity.py and commit the result")
        return
    with open(out, "w") as f:
        f.write(text)
    c = collections.Counter(row[2] for row in rows)
    print(f"{len(rows)} rules: {dict(c)}", file=sys.stderr)


def render(pin, rows):
    c = collections.Counter(r[2] for r in rows)
    cv = collections.Counter(r[2] for r in rows if r[1] != "-")
    total, validated = len(rows), sum(1 for r in rows if r[1] != "-")
    verified = sum(1 for r in rows if r[1] != "-" and r[4] != "-")
    pleno_only = sum(1 for r in rows if r[1] == "-" and r[4] != "-")
    lines = [
        "# kingfisher detector parity",
        "",
        "Machine-checked diff of the credential types",
        f"[mongodb/kingfisher](https://github.com/mongodb/kingfisher) (pin `{pin}`) detects",
        "against pleno-dlp detectors. Regenerate with",
        "`scripts/kingfisher-parity.py` (re-pin with `--kingfisher <clone>`); the",
        "method is in the script header. Do not hand-edit: `--check` fails on drift. `pkg/detectors/kingfisherparity_test.go` fails when a",
        "detector named below is no longer registered or the summary drifts",
        "from the machine block. Epic #817.",
        "",
        "kingfisher's catalog is the imported Betterleaks configuration, the",
        "selected Google Veles detectors, and a few first-party rules. The",
        "`validation` column is kingfisher's live-validation type (`-` =",
        "detection only). The `verified` column is how pleno-dlp verifies the",
        "rule (`-` = not verified): `native` (the credited detector's own",
        "Verify), `base:<Type>` (a catalog format routed to that provider's",
        "verifier, with paired credentials packed into its secret shape),",
        "`http` (a declarative request modelled on kingfisher's validator), or",
        "`signed` (an HMAC/SigV4-style signed request, OIDC signature, or",
        "offline key check). Paired credentials are resolved from the",
        "surrounding text the way kingfisher's `depends_on` does. The test",
        "fails when a kingfisher-validated rule has no pleno-dlp verification",
        "(issue #934). \"pleno-only verified\" counts rules kingfisher detects",
        "without validation that pleno-dlp still verifies (issue #950).",
        "",
        "Status:",
        "",
        "- **covered** — a provider-specific pleno-dlp detector fires on a",
        "  fixture synthesized from kingfisher's regex.",
        "- **partial** — pleno-dlp has a detector for the provider, but none",
        "  fired: a format variant, a stricter context or checksum rule, or a",
        "  fixture artefact. Each is a candidate for a format extension.",
        "- **missing** — no pleno-dlp detector for the credential type.",
        "- **context** — kingfisher hides the rule (`visible: false`): an",
        "  identifier, host, or URL that only feeds another rule's validation",
        "  and is never reported. Not a detection gap; pleno-dlp's paired",
        "  verifiers extract such context themselves.",
        "",
        "Rules pleno-dlp's native detectors miss are imported as detection-only",
        "formats by `scripts/kingfisher-catalog.py` (`pkg/detectors/catalog`).",
        "`betterleaks.generic-api-key` stays partial by design: importing",
        "Betterleaks' catch-all assignment rule adds hundreds of English-word",
        "findings on this repository alone, and `GenericHighEntropy` owns the",
        "generic class with stricter false-positive gates.",
        "",
        "## Summary",
        "",
        "| | covered | partial | missing | context | total |",
        "|---|---|---|---|---|---|",
        f"| all rules | {c['covered']} | {c['partial']} | {c['missing']} | {c['context']} | {total} |",
        f"| with kingfisher validation | {cv['covered']} | {cv['partial']} | {cv['missing']} | {cv['context']} | {validated} |",
        "",
        "| | kingfisher validates | pleno-dlp verifies |",
        "|---|---|---|",
        f"| validated parity | {validated} | {verified} |",
        f"| pleno-only verified | 0 | {pleno_only} |",
        "",
        "## Rules",
        "",
        "```parity-machine",
        f"kingfisher={pin}",
        f"total={total}",
        f"covered={c['covered']}",
        f"partial={c['partial']}",
        f"missing={c['missing']}",
        f"context={c['context']}",
        f"validated={validated}",
        f"verified={verified}",
        f"pleno_only_verified={pleno_only}",
    ]
    for rid, v, s, d, ver in rows:
        lines.append(f"rule={rid} validation={v} status={s} detector={d} verified={ver}")
    lines += ["```", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
