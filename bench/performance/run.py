#!/usr/bin/env python3
"""Secret scanner time, peak RSS and coverage gates on deterministic input shapes."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import platform
import random
import re
import signal
import statistics
import string
import subprocess
import tempfile
import tarfile
import time
import zipfile

COMPETITORS = ("gitleaks", "trufflehog", "betterleaks")
METRICS = ("seconds", "rss_bytes")
TASKS = {
    "logs": "Sparse multiline logs",
    "keywords": "Dense keyword rejection",
    "binary": "Binary input rejection",
    "archive": "ZIP expansion",
    "base64": "Base64 normalization",
    "empty": "Empty directory and process startup",
    "tiny": "Single short configuration",
    "many-small": "4096 small files",
    "deep-tree": "Nested paths and Unicode names",
    "long-line": "8 MiB unbroken line",
    "large-file": "64 MiB multiline file",
    "minified-json": "8 MiB minified JSON array",
    "nested-json": "Deeply nested JSON objects",
    "keyword-storm": "Dense overlapping keyword matches",
    "near-matches": "Malformed credential prefixes",
    "dense-findings": "2048 unique credentials",
    "duplicate-findings": "Repeated credentials in one file",
    "window-boundaries": "Credentials crossing scan window boundaries",
    "base64-lines": "Many short Base64 records",
    "base64-alignment": "Base64 runs at every modulo-four offset",
    "hex": "Hexadecimal normalization",
    "hex-mixed-case": "Mixed-case hexadecimal text",
    "hex-alignment": "Uppercase hex at even and odd offsets",
    "percent": "Percent escape normalization",
    "percent-boundaries": "Percent escapes crossing scan windows",
    "unicode-escape": "JSON Unicode escape normalization",
    "utf16le": "UTF-16 little endian text",
    "utf16be": "UTF-16 big endian text",
    "mixed-unicode": "UTF-8 multibyte log records",
    "crlf": "CRLF line endings",
    "gzip": "GZIP expansion",
    "tar": "TAR expansion",
    "nested-archive": "Nested ZIP expansion",
    "archive-many": "Many tiny ZIP members",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class CoverageError(ValueError):
    """A scan completed without the expected synthetic credential set."""


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
    (root / "tiny" / "config.txt").write_bytes(canary("tiny"))
    for i in range(4096):
        (root / "many-small" / f"{i}.txt").write_bytes(log + (canary("many-small") if i % 64 == 0 else b""))
    nested = root / "deep-tree"
    for i in range(48):
        nested = nested / f"level-{i}"
        nested.mkdir()
        (nested / "設定 file.txt").write_bytes(log + canary("deep-tree"))
    (root / "long-line" / "single.txt").write_bytes(b". " * (4 << 20) + canary("long-line").strip())
    (root / "large-file" / "large.txt").write_bytes(log * ((64 << 20) // len(log)) + canary("large-file"))
    item = b'{"id":123,"active":true,"status":"healthy"},'
    token = canary("minified-json").split(b"=")[1].strip()
    (root / "minified-json" / "data.json").write_bytes(b"[" + item * ((8 << 20) // len(item)) + b'{"token":"' + token + b'"}]')
    token = canary("nested-json").split(b"=")[1].strip()
    (root / "nested-json" / "data.json").write_bytes(b'{"data":' * 4096 + b'"' + token + b'"' + b"}" * 4096)
    storm = b"secret key token password access api auth "
    (root / "keyword-storm" / "storm.txt").write_bytes(storm * ((4 << 20) // len(storm)) + canary("keyword-storm"))
    near = b"ghp_123 github_pat_short AKIA0123456789 secret=short api_key=x\n"
    (root / "near-matches" / "near.txt").write_bytes(near * ((4 << 20) // len(near)) + canary("near-matches"))
    (root / "dense-findings" / "dense.txt").write_bytes(b"".join(canary("dense-findings") for _ in range(2048)))
    (root / "duplicate-findings" / "repeated.txt").write_bytes(canary("duplicate-findings") * 16384)
    for i, offset in enumerate((511, 1023, 2047, 31743, 32767, 65535)):
        (root / "window-boundaries" / f"{i}.txt").write_bytes(b" " * (offset - 24) + canary("window-boundaries"))
    (root / "base64-lines" / "records.txt").write_bytes(b"\n".join(base64.b64encode(log + canary("base64-lines")) for _ in range(256)))
    for name, alignments in (("base64-alignment", 4), ("hex-alignment", 2), ("percent-boundaries", 3)):
        for offset in range(alignments):
            body = log * 450 + canary(name) + log * 450
            if name == "base64-alignment":
                encoded = base64.b64encode(body)
            elif name == "hex-alignment":
                encoded = body.hex().upper().encode()
            else:
                encoded = b"".join(f"%{c:02X}".encode() for c in body)
            (root / name / f"{offset}.txt").write_bytes(b" " * offset + encoded)
    for name in ("hex", "hex-mixed-case", "percent", "unicode-escape", "utf16le", "utf16be", "mixed-unicode", "crlf", "gzip", "tar"):
        body = log * 16000 + canary(name)
        if name == "hex":
            encoded = body.hex().encode()
        elif name == "hex-mixed-case":
            encoded = "".join(c.upper() if (i // 2) % 2 else c for i, c in enumerate(body.hex())).encode()
        elif name == "percent":
            encoded = b"".join(f"%{c:02X}".encode() for c in body)
        elif name == "unicode-escape":
            encoded = b"".join(f"\\u{c:04x}".encode() for c in body)
        elif name.startswith("utf16"):
            encoded = (b"\xff\xfe" if name == "utf16le" else b"\xfe\xff") + body.decode().encode("utf-16-le" if name == "utf16le" else "utf-16-be")
        elif name == "mixed-unicode":
            encoded = ("正常に処理完了 🌍\n".encode() * 100000) + body
        elif name == "crlf":
            encoded = body.replace(b"\n", b"\r\n")
        elif name == "gzip":
            encoded = gzip.compress(body, mtime=0)
        else:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                info = tarfile.TarInfo("config.txt")
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            encoded = buffer.getvalue()
        suffix = {"gzip": ".gz", "tar": ".tar"}.get(name, ".txt")
        (root / name / ("data" + suffix)).write_bytes(encoded)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("inner.txt", date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, log * 1000 + canary("nested-archive"))
    with zipfile.ZipFile(root / "nested-archive" / "outer.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("inner.zip", date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, buffer.getvalue())
    with zipfile.ZipFile(root / "archive-many" / "many.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for i in range(512):
            info = zipfile.ZipInfo(f"{i}.txt", date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, log + canary("archive-many"))
    metadata = {}
    for name in TASKS:
        files = sorted(p for p in (root / name).rglob("*") if p.is_file())
        inventory = [(p.relative_to(root / name).as_posix(), p.stat().st_size, digest(p.read_bytes())) for p in files]
        metadata[name] = {"files": len(files), "bytes": sum(row[1] for row in inventory),
                          "sha256": digest(json.dumps(inventory).encode()), "canaries": len(expected[name])}
    return expected, metadata


def command(tool, binary, path, concurrency=8):
    if tool in ("before", "pleno-dlp"):
        return [binary, "scan", "filesystem", str(path), "--no-verify", "--pii-engine", "off", "--format", "json", "--quiet", "--concurrency", str(concurrency), "--max-size", str(128 << 20), "--no-default-excludes"]
    if tool in ("gitleaks", "betterleaks"):
        return [binary, "dir", str(path), "--no-banner", "--report-format", "json", "--report-path", "-", "--exit-code", "0", "--max-decode-depth", "1", "--max-archive-depth", "3"]
    return [binary, "filesystem", str(path), "--no-verification", "--no-update", "--json", "--log-level=-1", f"--concurrency={concurrency}", "--force-skip-binaries", "--max-decode-depth=1", "--archive-max-depth=3", "--fail-on-scan-errors"]


def observations(tool, data, expected):
    records = [json.loads(line) for line in data.splitlines() if line.strip()] if tool == "trufflehog" else json.loads(data)
    if tool in ("gitleaks", "betterleaks") and records is None:
        records = []
    if not isinstance(records, list) or any(not isinstance(rec, dict) for rec in records):
        raise ValueError("expected JSON findings")
    found = set()
    signature = []
    for rec in records:
        if tool in ("before", "pleno-dlp"):
            if rec["detector"] == "GitHub":
                found.add(rec["secret_hash"])
            signature.append(json.dumps(rec, sort_keys=True))
        elif tool in ("gitleaks", "betterleaks") and rec["RuleID"] == "github-pat":
            found.add(digest(rec["Secret"].encode()))
        elif tool == "trufflehog" and rec.get("DetectorName", "").lower() == "github":
            raw = rec["Raw"]
            if not raw.startswith("ghp_"):
                raw = base64.b64decode(raw).decode()
            found.add(digest(raw.encode()))
    if found != expected:
        raise CoverageError(f"{tool}: canary mismatch: missing={len(expected-found)} extra={len(found-expected)}")
    return len(records), digest("\n".join(sorted(signature)).encode()) if tool in ("before", "pleno-dlp") else None


def run_process(args, timeout=180, **kwargs):
    # time is a wrapper process: kill the entire scan group on timeout so an
    # orphan scanner cannot keep consuming resources during later samples.
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True, **kwargs) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def measure(tool, binary, path, expected, concurrency=8):
    args = command(tool, binary, path, concurrency)
    if platform.system() == "Darwin":
        timed = ["/usr/bin/time", "-l", *args]
    elif platform.system() == "Linux":
        timed = ["/usr/bin/time", "-f", "BENCH_RSS_KIB=%M", *args]
    else:
        raise RuntimeError("peak RSS measurement requires macOS or Linux")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GITLEAKS_", "BETTERLEAKS_"))}
    env["GOMAXPROCS"] = str(concurrency)
    started = time.perf_counter()
    process = run_process(timed, env=env, cwd=path.parent)
    elapsed = time.perf_counter() - started
    allowed = (0, 1) if tool in ("before", "pleno-dlp") else (0,)
    pattern = rb"(\d+)\s+maximum resident set size" if platform.system() == "Darwin" else rb"BENCH_RSS_KIB=(\d+)"
    match = re.search(pattern, process.stderr)
    if not match:
        raise RuntimeError("time did not report peak RSS")
    rss = int(match[1]) * (1 if platform.system() == "Darwin" else 1024)
    row = {"seconds": elapsed, "rss_bytes": rss, "exit_code": process.returncode}
    if process.returncode not in allowed:
        # Output may contain credential material; keep diagnostics to metadata.
        row["error"] = f"{tool} failed: exit={process.returncode}, stderr_sha256={digest(process.stderr)}"
        return row
    try:
        total, signature = observations(tool, process.stdout, expected)
        row.update(findings=total, signature=signature)
    except CoverageError as error:
        row["error"] = str(error)
    except (ValueError, KeyError, TypeError):
        # Preserve the measured cost even when coverage fails. These samples
        # are never eligible to establish performance parity.
        row["error"] = "invalid output or canary mismatch"
    return row


def summarize(samples, metric):
    medians = {tool: statistics.median(row[metric] for row in rows) for tool, rows in samples.items()}
    competitor = min((tool for tool in COMPETITORS if tool in medians), key=medians.get)
    return {"metric": metric, "medians": medians, "competitor": competitor,
            "ratio": medians["pleno-dlp"] / medians[competitor],
            "before_ratio": medians["before"] / medians[competitor] if "before" in medians else None,
            "pass": medians["pleno-dlp"] <= 1.2 * medians[competitor]}


def evaluate(samples, runs):
    errors = {tool: [r["error"] for r in rows if "error" in r]
              for tool, rows in samples.items() if any("error" in r for r in rows)}
    for tool in ("pleno-dlp", *COMPETITORS):
        if len(samples.get(tool, [])) != runs:
            errors.setdefault(tool, []).append("incomplete samples")
    measured = all(tool in samples for tool in ("pleno-dlp", *COMPETITORS)) and all(
        rows and all(all(metric in r for metric in METRICS) for r in rows)
        for rows in samples.values())
    metrics = {metric: summarize(samples, metric) for metric in METRICS} if measured else {}
    return {"metrics": metrics, "errors": errors,
            "pass": not errors and bool(metrics) and all(s["pass"] for s in metrics.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pleno-dlp-bin", required=True)
    parser.add_argument("--baseline-bin")
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--out", type=Path, default=Path("bench/results/performance.json"))
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--tasks", nargs="+", choices=TASKS, default=list(TASKS))
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0 or args.concurrency < 1:
        parser.error("runs and concurrency must be positive; warmups must be nonnegative")
    tools = {"pleno-dlp": str(Path(args.pleno_dlp_bin).resolve()),
             "gitleaks": str(Path("bench/.tools/gitleaks").resolve()),
             "trufflehog": str(Path("bench/.tools/trufflehog").resolve()),
             "betterleaks": str(Path("bench/.tools/betterleaks").resolve())}
    if args.baseline_bin:
        tools = {"before": str(Path(args.baseline_bin).resolve()), **tools}
    result = {"platform": platform.platform(), "processor": platform.processor(), "cpu_count": os.cpu_count(),
              "schema_version": 2, "started_at": datetime.now(timezone.utc).isoformat(),
              "harness_sha256": digest(Path(__file__).read_bytes()), "suite_complete": False,
              "gomaxprocs": args.concurrency, "tasks_requested": args.tasks, "runs": args.runs, "warmups": args.warmups, "tools": {}, "tasks": {}}
    for name, binary in tools.items():
        version = subprocess.check_output([binary, "version" if name in ("gitleaks", "betterleaks") else "--version"], stderr=subprocess.STDOUT).decode().strip()
        result["tools"][name] = {"version": version, "sha256": digest(Path(binary).read_bytes())}
    with tempfile.TemporaryDirectory(prefix="pleno-perf-") as temporary:
        root = Path(temporary)
        expected, metadata = fixtures(root)
        for name in args.tasks:
            genre = TASKS[name]
            samples = {tool: [] for tool in tools}
            warmup_errors = {}
            # Rotate the first tool each round to distribute order and cache effects.
            names = list(tools)
            for iteration in range(args.warmups + args.runs):
                offset = iteration % len(names)
                signatures = set()
                for tool in names[offset:] + names[:offset]:
                    try:
                        row = measure(tool, tools[tool], root / name, expected[name], args.concurrency)
                    except (ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                        row = {"error": str(error) if not isinstance(error, subprocess.TimeoutExpired) else "scan timeout"}
                    if "error" in row:
                        if iteration >= args.warmups:
                            samples[tool].append(row)
                        else:
                            warmup_errors.setdefault(tool, []).append(row["error"])
                        continue
                    if row["signature"]:
                        signatures.add(row["signature"])
                    if iteration >= args.warmups:
                        samples[tool].append(row)
                if len(signatures) > 1:
                    if iteration >= args.warmups:
                        samples["pleno-dlp"][-1]["error"] = "findings changed from baseline"
                    else:
                        warmup_errors.setdefault("pleno-dlp", []).append("findings changed from baseline")
            summary = evaluate(samples, args.runs)
            if warmup_errors:
                summary["pass"] = False
            result["tasks"][name] = {"genre": genre, "fixture": metadata[name], "samples": samples,
                                      "commands": {tool: command(tool, binary, root / name, args.concurrency) for tool, binary in tools.items()},
                                      "warmup_errors": warmup_errors, **summary}
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, indent=2) + "\n")
            detail = ", ".join(f"{metric}={m['ratio']:.3f}x {m['competitor']}" for metric, m in summary["metrics"].items())
            print(f"{name}: {detail}, errors={summary['errors'] or warmup_errors}, pass={summary['pass']}", flush=True)
    result["suite_complete"] = set(result["tasks"]) == set(TASKS)
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    if args.enforce and not all(task["pass"] for task in result["tasks"].values()):
        raise SystemExit("20% performance budget exceeded; see " + str(args.out))


if __name__ == "__main__":
    main()
