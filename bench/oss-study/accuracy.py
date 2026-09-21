#!/usr/bin/env python3
"""Independent CredData sample: upstream obfuscation and labelled-line scoring."""
import argparse
import binascii
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile

from study import CACHE, HERE, ROOT, digest, download, read_records, safe_path, save, scan

CRED = CACHE / "creddata"
DATA = CACHE / "creddata-sample"
META = CACHE / "creddata-meta"


def prepare_one(entry):
    repo_id = entry["repo_id"]
    rows = list(csv.DictReader((CRED / "meta" / (repo_id + ".csv")).open()))
    expected = {row["FileID"]: safe_path(row["FilePath"]) for row in rows}
    archive = CACHE / ("cred-" + repo_id + ".tar.gz")
    marker = CACHE / "cred-inventories" / (repo_id + ".json")
    if marker.exists():
        return json.loads(marker.read_text())
    try:
        found = set()
        archive_hash = None
        try:
            download(entry["repo"], entry["commit"], archive)
            archive_hash = digest(archive.read_bytes())
            with tarfile.open(archive) as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    path = safe_path(member.name)
                    file_id = digest(path.as_posix().encode())[:8]
                    if file_id in expected:
                        output = DATA / expected[file_id]
                        output.parent.mkdir(parents=True, exist_ok=True)
                        output.write_bytes(tar.extractfile(member).read())
                        found.add(file_id)
        except subprocess.CalledProcessError:
            pass  # GitHub rejects archives of some large trees; fetch selected blobs below.
        if found != set(expected):
            # GitHub archives honor export-ignore; CredData requires these test files too.
            bare = CACHE / ("cred-git-" + repo_id)
            if not bare.exists():
                subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True)
                subprocess.run(["git", "-C", str(bare), "remote", "add", "origin", "https://github.com/" + entry["repo"]], check=True)
                subprocess.run(["git", "-C", str(bare), "config", "remote.origin.promisor", "true"], check=True)
                subprocess.run(["git", "-C", str(bare), "config", "remote.origin.partialclonefilter", "blob:none"], check=True)
                subprocess.run(["git", "-C", str(bare), "fetch", "--filter=blob:none", "--depth=1", "origin", entry["commit"]], check=True, capture_output=True)
            tree = subprocess.check_output(["git", "-C", str(bare), "ls-tree", "-rz", entry["commit"]])
            for item in tree.split(b"\0"):
                if not item:
                    continue
                info, name = item.split(b"\t", 1)
                mode, kind, sha = info.split()
                file_id = digest(name)[:8]
                if file_id in expected and file_id not in found and mode in (b"100644", b"100755"):
                    output = DATA / expected[file_id]
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(subprocess.check_output(["git", "-C", str(bare), "cat-file", "blob", sha.decode()]))
                    found.add(file_id)
            if found != set(expected):
                raise ValueError(f"missing {len(set(expected) - found)} files")
        META.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(CRED / "meta" / (repo_id + ".csv"), META / (repo_id + ".csv"))
        result = {**entry, "files": len(found), "labels": dict(Counter(r["GroundTruth"] for r in rows)),
                  "archive_sha256": archive_hash}
        save(marker, result)
        archive.unlink(missing_ok=True)
        print(f"CredData {repo_id}: {len(found)} files", flush=True)
        return result
    except (subprocess.CalledProcessError, ValueError, tarfile.TarError) as error:
        # A failed acquisition is explicit, never scored as an undetected secret.
        print(f"CredData {repo_id}: acquisition failed ({type(error).__name__})", flush=True)
        return {**entry, "error": type(error).__name__, "labels": dict(Counter(r["GroundTruth"] for r in rows))}


def labels():
    """Collapse candidates to line starts; discard mixed-positive/negative lines."""
    grouped = defaultdict(list)
    for file in sorted(META.glob("*.csv")):
        for row in csv.DictReader(file.open()):
            grouped[(safe_path(row["FilePath"]).as_posix(), int(row["LineStart"]))].append(row)
    line_counts = {name: (DATA / name).read_bytes().count(b"\n") + 1 for name in {name for name, _ in grouped}}
    if any(line < 1 or line > line_counts[name] for name, line in grouped):
        raise ValueError("CredData label falls outside the acquired file")
    return grouped


def score(grouped, records):
    predicted = {(str(Path(r["path"]).relative_to(DATA)), r["line"]) for r in records}
    counts = Counter()
    categories = defaultdict(Counter)
    for key, rows in grouped.items():
        classes = {r["GroundTruth"] == "T" for r in rows}
        if len(classes) != 1:
            counts["ambiguous_lines_excluded"] += 1
            continue
        positive = classes.pop()
        hit = key in predicted
        outcome = ("tp" if hit else "fn") if positive else ("fp" if hit else "tn")
        counts[outcome] += 1
        for category in {r["Category"] for r in rows}:
            categories[category][outcome] += 1
    counts["unlabelled_predicted_lines"] = len(predicted - grouped.keys())
    counts["predicted_lines"] = len(predicted)
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    return {**counts, "precision_on_labelled_lines": tp / (tp + fp) if tp + fp else None,
            "recall_on_labelled_lines": tp / (tp + fn) if tp + fn else None,
            "f1_on_labelled_lines": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "categories": dict(categories)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["prepare", "scan", "probe"])
    args = parser.parse_args()
    pin = subprocess.check_output(["git", "-C", str(CRED), "rev-parse", "HEAD"]).decode().strip()
    if pin != "c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d":
        raise ValueError("check out the pinned CredData commit before preparing or scoring")
    if args.phase == "probe":
        sys.path.insert(0, str(CRED))
        from obfuscate_creds import create_new_key
        with tempfile.TemporaryDirectory(dir=CACHE) as temporary:
            root = Path(temporary)
            original, changed = root / "original.pem", root / "obfuscated.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(original)], check=True, capture_output=True)
            random.seed(0)
            changed.write_text("\n".join(create_new_key(original.read_text().splitlines())) + "\n")
            os.chmod(changed, 0o600)
            probe = {"creddata_commit": pin, "key_type": "generated RSA-2048, never used as a credential", "openssl_check": {}, "tools": {}}
            for file in (original, changed):
                check = subprocess.run(["openssl", "pkey", "-in", str(file), "-check", "-noout"], capture_output=True)
                probe["openssl_check"][file.name] = check.returncode
            assert probe["openssl_check"][original.name] == 0
            assert probe["openssl_check"][changed.name] != 0
            for tool in ("pleno-dlp", "trufflehog"):
                output = CACHE / "private" / ("pem-probe-" + tool + ".json")
                scan(tool, ROOT / "bench/.tools/oss-study" / tool, root, output)
                rows = read_records(tool, output)
                probe["tools"][tool] = dict(Counter(Path(r["path"]).name for r in rows if r["detector"].lower() in ("privatekey", "privatekeypem")))
            save(HERE / "pem-probe.json", probe)
        return
    if args.phase == "prepare":
        snapshot = json.loads((CRED / "snapshot.json").read_text())
        # Selection is fixed before seeing scanner output, independent of labels.
        selected = sorted(snapshot, key=lambda k: digest(k.encode()))[:100]
        manifest = [{"repo": snapshot[key].removeprefix("https://github.com/").removesuffix(".git"),
                     "commit": key[:40], "repo_id": f"{binascii.crc32(bytes.fromhex(key)):08x}"} for key in selected]
        with ThreadPoolExecutor(max_workers=4) as pool:
            inventory = list(pool.map(prepare_one, manifest))
        save(HERE / "creddata-inventory.json", {"commit": pin, "selection": "lowest 100 SHA256(snapshot key)", "repositories": inventory})
        if any("error" in entry for entry in inventory):
            raise RuntimeError("incomplete CredData sample; see creddata-inventory.json")
        marker = CACHE / "creddata-obfuscated.json"
        if not marker.exists():
            sys.path.insert(0, str(CRED))
            from obfuscate_creds import obfuscate_creds
            obfuscate_creds(str(META), str(DATA), 0)
            files = [(str(p.relative_to(DATA)), p.stat().st_size, digest(p.read_bytes())) for p in sorted(DATA.rglob("*")) if p.is_file()]
            save(marker, {"files": len(files), "bytes": sum(f[1] for f in files), "sha256": digest(json.dumps(files).encode())})
        return
    grouped = labels()
    without_keys = {key: rows for key, rows in grouped.items() if not any("Private Key" in r["Category"] for r in rows)}
    result = {"creddata_commit": pin, "scoring": "unique labelled line starts; T positive; F/X negative; mixed lines excluded",
              "corpus": json.loads((CACHE / "creddata-obfuscated.json").read_text()), "tools": {}}
    for iteration in range(3):
        names = ("pleno-dlp", "trufflehog") if iteration % 2 == 0 else ("trufflehog", "pleno-dlp")
        for tool in names:
            binary = ROOT / "bench/.tools/oss-study" / tool
            output = CACHE / "private" / ("creddata-" + tool + ".json")
            sample = {"scan": scan(tool, binary, DATA, output)}
            sample["score"] = score(grouped, read_records(tool, output))
            sample["without_private_keys"] = score(without_keys, read_records(tool, output))
            result["tools"].setdefault(tool, {**sample, "repeats": []})["repeats"].append(sample)
            print(tool, iteration + 1, {k: v for k, v in sample["score"].items() if k != "categories"}, flush=True)
    for tool_result in result["tools"].values():
        tool_result["score_stable"] = all(s["score"] == tool_result["score"] for s in tool_result["repeats"])
    save(HERE / "accuracy.json", result)


if __name__ == "__main__":
    main()
