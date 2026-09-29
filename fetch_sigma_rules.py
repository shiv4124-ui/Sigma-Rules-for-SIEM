#!/usr/bin/env python3
"""
Fetch every Sigma detection rule from SigmaHQ/sigma and build a searchable index.

Usage:
  python fetch_sigma_rules.py                    # fetch into ./sigma
  python fetch_sigma_rules.py --out data/sigma   # custom output dir
  python fetch_sigma_rules.py --include-deprecated
  python fetch_sigma_rules.py --force            # re-download even if unchanged
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

UPSTREAM_REPO = "SigmaHQ/sigma"
DEFAULT_BRANCH = "master"
API = "https://api.github.com"
TIMEOUT = 120
ATTACK_ID = re.compile(r"^[tgs]\d{4}", re.IGNORECASE)  # technique/group/software IDs


def session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Sigma-Rules-for-SIEM"
    token = os.getenv("GITHUB_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def latest_commit(s: requests.Session, repo: str, branch: str) -> str:
    r = s.get(f"{API}/repos/{repo}/commits/{branch}", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()["sha"]


def download_zip(s: requests.Session, repo: str, ref: str) -> zipfile.ZipFile:
    url = f"https://codeload.github.com/{repo}/zip/{ref}"
    print(f"Downloading {url} ...")
    r = s.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    print(f"Downloaded {len(r.content) / 1_048_576:.1f} MB")
    return zipfile.ZipFile(io.BytesIO(r.content))


def is_rule_path(parts: list[str], include_deprecated: bool) -> bool:
    if len(parts) < 2 or not parts[-1].endswith((".yml", ".yaml")):
        return False
    top = parts[0]
    if top.startswith("rules"):
        return True
    return include_deprecated and top == "deprecated"


def extract_rules(zf: zipfile.ZipFile, rules_dir: Path, include_deprecated: bool) -> list[Path]:
    if rules_dir.exists():
        shutil.rmtree(rules_dir)
    written = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        parts = info.filename.split("/")[1:]
        if not is_rule_path(parts, include_deprecated):
            continue
        dest = rules_dir.joinpath(*parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zf.read(info))
        written.append(dest)
    return written


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_rule(path: Path, root: Path) -> dict | None:
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        print(f"  ! could not parse {path}: {exc}", file=sys.stderr)
        return None
    doc = next((d for d in docs if isinstance(d, dict) and d.get("title")), None)
    if doc is None:
        return None
    logsource = doc.get("logsource") or {}
    rule_type = "correlation" if "correlation" in doc else "detection"
    return {
        "id": doc.get("id", ""),
        "title": doc.get("title", ""),
        "status": doc.get("status", ""),
        "level": doc.get("level", ""),
        "type": rule_type,
        "product": logsource.get("product", ""),
        "category": logsource.get("category", ""),
        "service": logsource.get("service", ""),
        "tags": as_list(doc.get("tags")),
        "author": doc.get("author", ""),
        "date": str(doc.get("date", "")),
        "modified": str(doc.get("modified", "")),
        "description": (doc.get("description") or "").strip(),
        "path": path.relative_to(root).as_posix(),
    }


def write_index(entries: list[dict], out: Path) -> None:
    entries.sort(key=lambda e: e["path"])
    (out / "index.json").write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")

    fields = [k for k in entries[0].keys() if k != "description"] if entries else []
    with (out / "index.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for e in entries:
            w.writerow({**e, "tags": ";".join(map(str, e["tags"]))})

    tactics = Counter(
        t.split(".", 1)[1] for e in entries for t in e["tags"]
        if isinstance(t, str) and t.startswith("attack.") and not ATTACK_ID.match(t[7:])
    )
    stats = {
        "total_rules": len(entries),
        "by_folder": Counter(e["path"].split("/")[1] for e in entries),
        "by_level": Counter(e["level"] or "unset" for e in entries),
        "by_status": Counter(e["status"] or "unset" for e in entries),
        "by_product": Counter(e["product"] or "unset" for e in entries),
        "by_type": Counter(e["type"] for e in entries),
        "top_attack_tactics": dict(tactics.most_common(20)),
    }
    stats = {k: dict(sorted(v.items(), key=lambda kv: -kv[1])) if isinstance(v, Counter) else v
             for k, v in stats.items()}
    (out / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch all Sigma rules from SigmaHQ.")
    ap.add_argument("--out", default="sigma", help="output directory (default: sigma)")
    ap.add_argument("--repo", default=UPSTREAM_REPO)
    ap.add_argument("--branch", default=DEFAULT_BRANCH)
    ap.add_argument("--include-deprecated", action="store_true")
    ap.add_argument("--force", action="store_true", help="download even if upstream is unchanged")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    meta_file = out / "metadata.json"
    s = session()

    sha = latest_commit(s, args.repo, args.branch)
    previous = json.loads(meta_file.read_text()) if meta_file.exists() else {}
    if not args.force and previous.get("upstream_commit") == sha \
            and previous.get("include_deprecated") == args.include_deprecated:
        print(f"Already up to date with {args.repo}@{sha[:10]}. Nothing to do.")
        return 0

    zf = download_zip(s, args.repo, sha)
    rules_dir = out / "rules"
    files = extract_rules(zf, rules_dir, args.include_deprecated)
    print(f"Extracted {len(files)} rule files")

    entries = [e for e in (parse_rule(p, out) for p in files) if e]
    write_index(entries, out)

    meta = {
        "upstream_repo": args.repo,
        "upstream_branch": args.branch,
        "upstream_commit": sha,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rule_files": len(files),
        "indexed_rules": len(entries),
        "include_deprecated": args.include_deprecated,
        "license": "Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License",
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Indexed {len(entries)} rules from {args.repo}@{sha[:10]} into {out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
