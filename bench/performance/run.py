#!/usr/bin/env python3
"""Five subsystem performance gates; Python standard library, macOS/Linux."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import statistics
import string
import subprocess
import tempfile
import time
import zipfile

TASKS = {
    "logs": ("Whole-file structural matching", "seconds"),
    "keywords": ("Keyword dispatch", "seconds"),
    "binary": ("Binary input rejection", "rss_bytes"),
    "archive": ("Archive expansion", "rss_bytes"),
    "base64": ("Encoded input normalization", "rss_bytes"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixtures(root):
    rng = random.Random(2048)
    expected = {name: set() for name in TASKS}
    for name in TASKS:
        (root / name).mkdir()

    def canary(name):
        token = "ghp_" + "".join(rng.choices(string.ascii_letters + string.digits, k=36))
        expected[name].add(digest(token.encode()))
        return ("\naccess_token=" + token + "\n").encode()

    log = b"2026-09-21 INFO request=GET /healthz status=200 latency_ms=12.4\n"
    code = b"// API documentation: access token, password, secret key.\nconst status = 200; // health check\n"
    for i in range(8):
        (root / "logs" / f"{i}.txt").write_bytes(log * ((8 << 20) // len(log)) + canary("logs"))
        body = log * 40000 + canary("base64")
        (root / "base64" / f"{i}.txt").write_bytes(b"payload=" + base64.b64encode(body) + b"\n")
    for i in range(64):
        (root / "keywords" / f"{i}.txt").write_bytes(code * ((1 << 20) // len(code)) + (canary("keywords") if i == 0 else b""))
    for i in range(32):
        (root / "binary" / f"{i}.bin").write_bytes(b"\x00" + b"x" * (8 << 20))
    (root / "binary" / "config.txt").write_bytes(canary("binary"))
    for i in range(4):
        with zipfile.ZipFile(root / "archive" / f"{i}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            for j in range(8):
                info = zipfile.ZipInfo(f"{j}.txt", date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, log * ((1 << 20) // len(log)) + canary("archive"))
    metadata = {}
    for name in TASKS:
        files = sorted((root / name).iterdir())
        inventory = [(p.name, p.stat().st_size, digest(p.read_bytes())) for p in files]
        metadata[name] = {"files": len(files), "bytes": sum(row[1] for row in inventory),
                          "sha256": digest(json.dumps(inventory).encode()), "canaries": len(expected[name])}
    return expected, metadata


def command(tool, binary, path):
    if tool in ("before", "pleno-dlp"):
        return [binary, "scan", "filesystem", str(path), "--no-verify", "--pii-engine", "off", "--format", "json", "--quiet", "--concurrency", "8"]
    if tool == "gitleaks":
        return [binary, "dir", str(path), "--no-banner", "--report-format", "json", "--report-path", "-", "--exit-code", "0", "--max-decode-depth", "1", "--max-archive-depth", "3"]
    return [binary, "filesystem", str(path), "--no-verification", "--no-update", "--json", "--log-level=-1", "--concurrency=8", "--force-skip-binaries", "--max-decode-depth=1", "--archive-max-depth=3", "--fail-on-scan-errors"]


def observations(tool, data, expected):
    records = [json.loads(line) for line in data.splitlines() if line.strip()] if tool == "trufflehog" else json.loads(data)
    found = set()
    signature = []
    for rec in records:
        if tool in ("before", "pleno-dlp"):
            if rec["detector"] == "GitHub":
                found.add(rec["secret_hash"])
            signature.append(json.dumps({k: rec.get(k) for k in ("detector", "secret_hash", "secret_hash_v2", "source", "extra_data", "verdict")}, sort_keys=True))
        elif tool == "gitleaks" and rec["RuleID"] == "github-pat":
            found.add(digest(rec["Secret"].encode()))
        elif tool == "trufflehog" and rec.get("DetectorName", "").lower() == "github":
            raw = rec["Raw"]
            if not raw.startswith("ghp_"):
                raw = base64.b64decode(raw).decode()
            found.add(digest(raw.encode()))
    if found != expected:
        raise ValueError(f"{tool}: canary mismatch: missing={len(expected-found)} extra={len(found-expected)}")
    return len(records), digest("\n".join(sorted(signature)).encode()) if signature else None


def measure(tool, binary, path, expected):
    args = command(tool, binary, path)
    if platform.system() == "Darwin":
        timed = ["/usr/bin/time", "-l", *args]
    elif platform.system() == "Linux":
        timed = ["/usr/bin/time", "-f", "BENCH_RSS_KIB=%M", *args]
    else:
        raise RuntimeError("peak RSS measurement requires macOS or Linux")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_")}
    env["GOMAXPROCS"] = "8"
    started = time.perf_counter()
    process = subprocess.run(timed, capture_output=True, env=env, timeout=180)
    elapsed = time.perf_counter() - started
    allowed = (0, 1) if tool in ("before", "pleno-dlp") else (0,)
    if process.returncode not in allowed:
        # Output may contain credential material; keep failure diagnostics bounded to metadata.
        raise RuntimeError(f"{tool} failed: exit={process.returncode}, stderr_sha256={digest(process.stderr)}")
    total, signature = observations(tool, process.stdout, expected)
    pattern = rb"(\d+)\s+maximum resident set size" if platform.system() == "Darwin" else rb"BENCH_RSS_KIB=(\d+)"
    match = re.search(pattern, process.stderr)
    if not match:
        raise RuntimeError("time did not report peak RSS")
    rss = int(match[1]) * (1 if platform.system() == "Darwin" else 1024)
    return {"seconds": elapsed, "rss_bytes": rss, "findings": total, "signature": signature}


def summarize(samples, metric):
    medians = {tool: statistics.median(row[metric] for row in rows) for tool, rows in samples.items()}
    competitor = min(("gitleaks", "trufflehog"), key=medians.get)
    return {"metric": metric, "medians": medians, "competitor": competitor,
            "ratio": medians["pleno-dlp"] / medians[competitor],
            "before_ratio": medians["before"] / medians[competitor] if "before" in medians else None,
            "pass": medians["pleno-dlp"] <= 1.2 * medians[competitor]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pleno-dlp-bin", required=True)
    parser.add_argument("--baseline-bin")
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--out", type=Path, default=Path("bench/results/performance.json"))
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 1:
        parser.error("runs and warmups must be positive")
    tools = {"pleno-dlp": str(Path(args.pleno_dlp_bin).resolve()),
             "gitleaks": str(Path("bench/.tools/gitleaks").resolve()),
             "trufflehog": str(Path("bench/.tools/trufflehog").resolve())}
    if args.baseline_bin:
        tools = {"before": str(Path(args.baseline_bin).resolve()), **tools}
    result = {"platform": platform.platform(), "processor": platform.processor(), "cpu_count": os.cpu_count(),
              "gomaxprocs": 8, "runs": args.runs, "warmups": args.warmups, "tools": {}, "tasks": {}}
    for name, binary in tools.items():
        version = subprocess.check_output([binary, "version" if name == "gitleaks" else "--version"], stderr=subprocess.STDOUT).decode().strip()
        result["tools"][name] = {"version": version, "sha256": digest(Path(binary).read_bytes())}
    with tempfile.TemporaryDirectory(prefix="pleno-perf-") as temporary:
        root = Path(temporary)
        expected, metadata = fixtures(root)
        for name, (genre, metric) in TASKS.items():
            samples = {tool: [] for tool in tools}
            # Rotate the first tool each round to distribute order and cache effects.
            names = list(tools)
            for iteration in range(args.warmups + args.runs):
                offset = iteration % len(names)
                signatures = set()
                for tool in names[offset:] + names[:offset]:
                    row = measure(tool, tools[tool], root / name, expected[name])
                    if row["signature"]:
                        signatures.add(row["signature"])
                    if iteration >= args.warmups:
                        samples[tool].append(row)
                if len(signatures) > 1:
                    raise ValueError(f"{name}: pleno-dlp findings changed from baseline")
            summary = summarize(samples, metric)
            result["tasks"][name] = {"genre": genre, "fixture": metadata[name], "samples": samples, **summary}
            print(f"{name}: {summary['ratio']:.3f}x {summary['competitor']} ({metric}), pass={summary['pass']}", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    if args.enforce and not all(task["pass"] for task in result["tasks"].values()):
        raise SystemExit("20% performance budget exceeded; see " + str(args.out))


if __name__ == "__main__":
    main()
