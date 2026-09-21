#!/usr/bin/env python3
"""Pinned OSS snapshot comparison. Python stdlib; never publish raw findings."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import random
import signal
import statistics
import subprocess
import sys
import tarfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "bench/.cache/oss-study"
HERE = Path(__file__).resolve().parent
REPOS = """torvalds/linux kubernetes/kubernetes microsoft/vscode python/cpython nodejs/node
golang/go rust-lang/rust django/django pallets/flask fastapi/fastapi
psf/requests numpy/numpy pandas-dev/pandas scikit-learn/scikit-learn scipy/scipy
facebook/react vuejs/core sveltejs/svelte angular/angular vitejs/vite
webpack/webpack expressjs/express nestjs/nest denoland/deno oven-sh/bun
rails/rails laravel/framework symfony/symfony spring-projects/spring-boot elastic/elasticsearch
apache/kafka apache/spark apache/httpd nginx/nginx curl/curl
openssl/openssl git/git redis/redis valkey-io/valkey postgres/postgres
sqlite/sqlite prometheus/prometheus grafana/grafana envoyproxy/envoy caddyserver/caddy
moby/moby containerd/containerd helm/helm ansible/ansible neovim/neovim""".split()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def go_version(binary):
    info = subprocess.run(["go", "version", "-m", str(binary)], capture_output=True, text=True)
    # Some official release binaries do not expose readable Go build metadata.
    return info.stdout.splitlines()[0].split(": ", 1)[1] if info.returncode == 0 else "unavailable from release binary"


def command(tool, binary, path):
    # Same detection-only profile as bench/performance, frozen for this study.
    if tool == "pleno-dlp":
        return [str(binary), "scan", "filesystem", str(path), "--no-verify", "--pii-engine", "off",
                "--format", "json", "--quiet", "--concurrency", "8", "--no-default-excludes", "--max-size", str(1 << 30)]
    return [str(binary), "filesystem", str(path), "--no-verification", "--no-update", "--json", "--log-level=-1",
            "--concurrency=8", "--force-skip-binaries", "--force-skip-archives", "--max-decode-depth=1",
            "--archive-max-depth=3", "--fail-on-scan-errors"]


def download(repo, commit, destination):
    subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
                    "--retry", "3", "--max-time", "600", "-o", str(destination),
                    f"https://codeload.github.com/{repo}/tar.gz/{commit}"], check=True)


def safe_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        raise ValueError("unsafe archive member")
    return Path(*path.parts[1:])


def tree_inventory(tree):
    inventory = []
    for path in tree.rglob("*"):
        if path.is_symlink():
            raise ValueError("corpus contains an unexpected symlink")
        if path.is_file():
            inventory.append((path.relative_to(tree).as_posix(), path.stat().st_size, digest(path.read_bytes())))
    return sorted(inventory)


def prepare_one(entry):
    slug = entry["repo"].replace("/", "__")
    target = CACHE / "trees" / slug
    meta = CACHE / "inventories" / (slug + ".json")
    if meta.exists():
        prior = json.loads(meta.read_text())
        if prior["commit"] != entry["commit"]:
            raise ValueError("cached commit differs; use a fresh cache")
        return prior
    archive = CACHE / (slug + ".tar.gz")
    download(entry["repo"], entry["commit"], archive)
    inventory, skipped = [], Counter()
    with tarfile.open(archive) as tar:
        for member in tar:
            if member.isdir():
                continue
            if not member.isfile():
                skipped["non_regular"] += 1
                continue
            path = safe_path(member.name)
            if member.size > 1 << 20:
                skipped["over_1_mib"] += 1
                continue
            body = tar.extractfile(member).read()
            if b"\0" in body:
                skipped["nul_byte"] += 1
                continue
            try:
                body.decode("utf-8")
            except UnicodeDecodeError:
                skipped["non_utf8"] += 1
                continue
            output = target / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(body)
            inventory.append((path.as_posix(), len(body), digest(body)))
    inventory.sort()
    actual = tree_inventory(target)
    result = {**entry, "files": len(actual), "bytes": sum(x[1] for x in actual),
              "inventory_sha256": digest(json.dumps(actual).encode()),
              "archive_retained_files": len(inventory), "archive_retained_bytes": sum(x[1] for x in inventory),
              "archive_inventory_sha256": digest(json.dumps(inventory).encode()),
              "archive_sha256": digest(archive.read_bytes()), "excluded": dict(skipped)}
    save(meta, result)
    archive.unlink()
    print(f"prepared {entry['repo']}: {result['files']} files, {result['bytes']/2**20:.1f} MiB", flush=True)
    return result


def competing_work(processes, own_pid):
    rows = [line.strip().split(None, 3) for line in processes.splitlines()]
    rows = [row for row in rows if len(row) == 4]
    own = {str(own_pid)}
    while True:
        descendants = own | {pid for pid, parent, _, _ in rows if parent in own}
        if descendants == own:
            break
        own = descendants
    for pid, _, name, args in rows:
        if pid in own:
            continue
        if name.endswith(".test") or (name == "go" and re.search(r"(?:^|/)go (test|build|run)(?:\s|$)", args)):
            return True
        if name in ("trufflehog", "pleno-dlp", "betterleaks", "gitleaks"):
            return True
        if "/pkg/tool/" in args and name in ("compile", "link"):
            return True
    return False


def busy():
    if os.environ.get("OSS_STUDY_ALLOW_CONTENTION") == "1":
        return False
    # ucomm is the executable name; Darwin truncates the path-oriented comm column.
    return competing_work(subprocess.check_output(["ps", "-ww", "-axo", "pid=,ppid=,ucomm=,args="], text=True), os.getpid())


def environment():
    result = {"platform": platform.platform(), "cpu_count": os.cpu_count()}
    if sys.platform == "darwin":
        model, memory = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string", "hw.memsize"], text=True).splitlines()
        result.update(cpu_model=model, memory_bytes=int(memory))
    elif sys.platform == "linux":
        cpu = Path("/proc/cpuinfo").read_text()
        model = re.search(r"^(?:model name|Hardware)\s*:\s*(.+)$", cpu, re.MULTILINE)
        memory = re.search(r"^MemTotal:\s*(\d+) kB", Path("/proc/meminfo").read_text(), re.MULTILINE)
        result.update(cpu_model=model[1] if model else platform.machine(), memory_bytes=int(memory[1]) * 1024)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        result["runner"] = "GitHub Actions standard hosted runner"
        result["workflow_run"] = f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    return result


def scan(tool, binary, path, output, timeout=1200, canary_hash=None):
    discarded = 0
    while True:
        while busy():
            print("Waiting for other scanners / Go builds and tests", flush=True)
            time.sleep(10)
        result = measure(tool, binary, path, output, timeout, canary_hash)
        if result is not None and not busy():
            return {**result, "discarded_contended_attempts": discarded}
        discarded += 1
        print(f"Discarded contended {tool} trial; repeating after competing work finishes", flush=True)
        time.sleep(5)


def measure(tool, binary, path, output, timeout=1200, canary_hash=None):
    args = command(tool, binary, path)
    timer = ["/usr/bin/time", "-l"] if sys.platform == "darwin" else ["/usr/bin/time", "-f", "BENCH_TIME=%U,%S,%M"]
    # A clean environment also prevents inherited provider credentials/configuration.
    env = {"PATH": os.environ["PATH"], "GOMAXPROCS": "8", "HOME": str(CACHE / "empty-home")}
    Path(env["HOME"]).mkdir(exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    started = time.perf_counter()
    started_unix = time.time()
    stop = threading.Event()
    interfered = threading.Event()
    with output.open("wb") as out:
        os.chmod(output, 0o600)
        process = subprocess.Popen(timer + args, stdout=out, stderr=subprocess.PIPE, env=env, cwd=env["HOME"], start_new_session=True)

        def monitor():
            while not stop.wait(0.5):
                if busy():
                    interfered.set()
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    return

        watcher = threading.Thread(target=monitor, daemon=True)
        watcher.start()
        try:
            _, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        finally:
            stop.set()
            watcher.join()
    elapsed = time.perf_counter() - started
    output.with_suffix(".stderr").write_bytes(stderr)
    os.chmod(output.with_suffix(".stderr"), 0o600)
    if interfered.is_set():
        return None
    if process.returncode not in ((0, 1) if tool == "pleno-dlp" else (0,)):
        raise RuntimeError(f"{tool} exit={process.returncode}, stderr_sha256={digest(stderr)}")
    if sys.platform == "darwin":
        rss = int(re.search(rb"(\d+)\s+maximum resident set size", stderr)[1])
        cpu = re.search(rb"([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys", stderr)
        user, system = float(cpu[2]), float(cpu[3])
    else:
        cpu = re.search(rb"BENCH_TIME=([\d.]+),([\d.]+),(\d+)", stderr)
        user, system, rss = float(cpu[1]), float(cpu[2]), int(cpu[3]) * 1024
    records = read_records(tool, output)
    if canary_hash:
        canaries = [r for r in records if r["hash"] == canary_hash and r["detector"].lower() == "github"]
        if len(canaries) != 1:
            raise ValueError(f"{tool}: scan must find exactly one control token")
        records = [r for r in records if r["hash"] != canary_hash]
    return {"seconds": elapsed, "user_seconds": user, "system_seconds": system,
            "started_unix": started_unix, "load_average_after": list(os.getloadavg()),
            "rss_bytes": rss, "exit_code": process.returncode, "findings": len(records),
            "canary_found": bool(canary_hash),
            "detectors": dict(Counter(r["detector"] for r in records)),
            "locations_sha256": digest(json.dumps(sorted(records, key=lambda r: json.dumps(r, sort_keys=True)), sort_keys=True).encode())}


def read_records(tool, output):
    data = output.read_bytes()
    records = json.loads(data) if tool == "pleno-dlp" else [json.loads(line) for line in data.splitlines() if line.strip()]
    normalized = []
    for row in records:
        if tool == "pleno-dlp":
            assert not row["verified"] and row["verdict"] == "unverified"
            meta = row["source"]["metadata"]
            normalized.append({"path": meta["path"], "line": meta["line"], "detector": row["detector"],
                               "hash": row["secret_hash"], "start": row.get("start"), "end": row.get("end")})
        else:
            assert not row["Verified"]
            meta = row["SourceMetadata"]["Data"]["Filesystem"]
            normalized.append({"path": meta["file"], "line": meta["line"], "detector": row["DetectorName"],
                               "hash": digest(row["Raw"].encode()), "start": None, "end": None})
    return normalized


def check_resume(prior, current):
    # Python versions differ in whether platform() appends the Mach-O suffix.
    assert prior["platform"].removesuffix("-Mach-O") == current["platform"].removesuffix("-Mach-O"), "resume platform changed"
    for key in ("cpu_count", "gomaxprocs", "source_commit", "runs", "warmups", "measurement_condition", "input_inventories"):
        assert prior.get(key) == current[key], f"resume configuration changed: {key}"
    for tool in current["tools"]:
        for key in ("sha256", "version", "command"):
            assert prior["tools"][tool][key] == current["tools"][tool][key], f"resume tool changed: {tool} {key}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["prepare", "scan", "verify"])
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--resume", action="store_true", help="reuse completed repositories after checking tool identity")
    args = parser.parse_args()
    CACHE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(CACHE, 0o700)
    manifest_path = HERE / "manifest.json"
    if args.phase == "prepare":
        if manifest_path.exists():
            entries = json.loads(manifest_path.read_text())
        else:
            entries = []
            for repo in REPOS:
                sha = subprocess.check_output(["gh", "api", f"repos/{repo}/commits/HEAD", "--jq", ".sha"]).decode().strip()
                assert re.fullmatch("[0-9a-f]{40}", sha)
                entries.append({"repo": repo, "commit": sha})
            save(manifest_path, entries)
        with ThreadPoolExecutor(max_workers=4) as pool:
            inventory = list(pool.map(prepare_one, entries))
        save(HERE / "inventory.json", inventory)
        return
    if args.phase == "verify":
        unique = {}
        file_count = 0
        for entry in json.loads((HERE / "inventory.json").read_text()):
            tree = CACHE / "trees" / entry["repo"].replace("/", "__")
            inventory = tree_inventory(tree)
            for _, size, sha in inventory:
                unique[sha] = size
                file_count += 1
            if digest(json.dumps(inventory).encode()) != entry["inventory_sha256"]:
                raise ValueError(f"input integrity failed: {entry['repo']}")
        save(HERE / "input-verification.json", {"inventories_match": True, "files": file_count,
            "unique_file_contents": len(unique), "unique_content_bytes": sum(unique.values())})
        print("All 50 retained inventories match their acquisition hashes")
        return
    if args.runs < 3:
        parser.error("at least three timed repeats required")
    tools = {name: ROOT / "bench/.tools/oss-study" / name for name in ("pleno-dlp", "trufflehog")}
    result_path = HERE / "results.json"
    build_info = subprocess.check_output(["go", "version", "-m", str(tools["pleno-dlp"])]).decode()
    revision = re.search(r"vcs.revision=([0-9a-f]{40})", build_info)
    if not revision:
        raise ValueError("pleno-dlp binary must contain source revision metadata")
    inventory = json.loads((HERE / "inventory.json").read_text())
    result = {**environment(), "gomaxprocs": 8,
              "input_inventories": [{"repo": entry["repo"], "sha256": entry["inventory_sha256"]} for entry in inventory],
              "measurement_condition": "shared load reference" if os.environ.get("OSS_STUDY_ALLOW_CONTENTION") == "1" else "contention guarded",
              "source_commit": revision[1],
              "runs": args.runs, "warmups": 1, "tools": {}, "repositories": {}}
    for name, binary in tools.items():
        result["tools"][name] = {"sha256": digest(binary.read_bytes()),
            "version": subprocess.check_output([str(binary), "--version"], stderr=subprocess.STDOUT).decode().strip(),
            "go_version": go_version(binary),
            "command": command(name, binary.name, Path("CORPUS"))}
    if args.resume and result_path.exists():
        prior = json.loads(result_path.read_text())
        check_resume(prior, result)
        result["repositories"] = prior["repositories"]
        result["resumed_repositories"] = list(prior["repositories"])
    for entry in inventory:
        repo = entry["repo"]
        if repo in result["repositories"]:
            continue
        slug = repo.replace("/", "__")
        rng = random.Random(repo)
        token = "ghp_" + "".join(rng.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=36))
        canary_path = CACHE / "trees" / slug / ".oss-study-control.txt"
        assert not canary_path.exists(), "control path must not overwrite corpus content"
        canary_path.write_text("access_token=" + token + "\n")
        samples = {tool: [] for tool in tools}
        try:
            for iteration in range(args.runs + 1):
                names = list(tools) if iteration % 2 == 0 else list(reversed(tools))
                for tool in names:
                    row = scan(tool, tools[tool], CACHE / "trees" / slug, CACHE / "private" / slug / (tool + ".json"), canary_hash=digest(token.encode()))
                    if iteration:
                        samples[tool].append(row)
        finally:
            canary_path.unlink()
        result["repositories"][repo] = samples
        save(result_path, result)
        medians = {t: statistics.median(r["seconds"] for r in rows) for t, rows in samples.items()}
        print(f"{repo}: pleno={medians['pleno-dlp']:.3f}s trufflehog={medians['trufflehog']:.3f}s", flush=True)


if __name__ == "__main__":
    main()
