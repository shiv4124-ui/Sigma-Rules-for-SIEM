#!/usr/bin/env python3
"""
Fetch every Sigma detection rule from SigmaHQ/sigma, sort them into platform folders
(windows, linux, macos, cloud, network, web, application, other) and build an index.

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

# Platform folders the rules are sorted into.
OS_PLATFORMS = {"windows", "linux", "macos"}
FOLDER_PLATFORMS = {"windows", "linux", "macos", "cloud", "network", "web", "application"}
CLOUD_PRODUCTS = {"aws", "azure", "gcp", "m365", "okta", "onelogin", "google_workspace",
                  "github", "bitbucket", "cisco_duo", "jfrog", "salesforce"}
NETWORK_PRODUCTS = {"zeek", "cisco", "juniper", "fortios", "fortigate", "huawei", "paloalto",
                    "checkpoint", "sonicwall", "f5"}
NETWORK_CATEGORIES = {"firewall", "dns"}
WEB_CATEGORIES = {"webserver", "proxy"}
RULESET_NAMES = {"rules": "core", "deprecated": "deprecated"}


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


def slug(value) -> str:
    text = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9_.-]+", "_", text) or "generic"


def ruleset_name(top: str) -> str:
    return RULESET_NAMES.get(top, top.replace("rules-", ""))


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def platform_for(parts: list[str], doc: dict) -> tuple[str, str]:
    """Return (platform, subfolder) for a rule, e.g. ('windows', 'process_creation')."""
    ls = doc.get("logsource") or {}
    product = slug(ls.get("product")) if ls.get("product") else ""
    category = slug(ls.get("category")) if ls.get("category") else ""
    service = slug(ls.get("service")) if ls.get("service") else ""

    # 1) Operating systems: group by log category/service (process_creation, security, ...)
    if product in OS_PLATFORMS:
        return product, category or service or "generic"

    # 2) SigmaHQ already organises core/hunting rules by folder: rules/cloud/aws/..., rules/network/zeek/...
    folders = parts[1:-1]
    for i, seg in enumerate(folders):
        if seg in FOLDER_PLATFORMS:
            sub = folders[i + 1] if i + 1 < len(folders) else (product or category or "generic")
            return seg, slug(sub)

    # 3) Fall back to the rule's logsource (mainly emerging-threat rules, which are sorted by year)
    if product in CLOUD_PRODUCTS:
        return "cloud", product
    if product in NETWORK_PRODUCTS or category in NETWORK_CATEGORIES:
        return "network", product or category
    if category in WEB_CATEGORIES:
        return "web", category
    if product:
        return "application", product
    return "other", category or service or "generic"


def load_yaml_docs(raw: bytes, name: str) -> list:
    try:
        return list(yaml.safe_load_all(raw.decode("utf-8")))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        print(f"  ! could not parse {name}: {exc}", file=sys.stderr)
        return []


def build_entry(doc: dict, path: Path, root: Path, platform: str, ruleset: str, upstream: str) -> dict:
    logsource = doc.get("logsource") or {}
    return {
        "id": doc.get("id", ""),
        "title": doc.get("title", ""),
        "platform": platform,
        "ruleset": ruleset,
        "status": doc.get("status", ""),
        "level": doc.get("level", ""),
        "type": "correlation" if "correlation" in doc else "detection",
        "product": logsource.get("product", ""),
        "category": logsource.get("category", ""),
        "service": logsource.get("service", ""),
        "tags": as_list(doc.get("tags")),
        "author": doc.get("author", ""),
        "date": str(doc.get("date", "")),
        "modified": str(doc.get("modified", "")),
        "description": (doc.get("description") or "").strip(),
        "path": path.relative_to(root).as_posix(),
        "upstream_path": upstream,
    }


def extract_rules(zf: zipfile.ZipFile, rules_dir: Path, include_deprecated: bool) -> tuple[list[dict], int]:
    """Write every rule into rules_dir/<platform>/<subfolder>/<file>; return (index entries, file count)."""
    if rules_dir.exists():
        shutil.rmtree(rules_dir)  # start clean so rules removed upstream disappear here too
    entries = []
    count = 0
    for info in sorted(zf.infolist(), key=lambda i: i.filename):
        if info.is_dir():
            continue
        parts = info.filename.split("/")[1:]  # drop the "sigma-<ref>/" root folder
        if not is_rule_path(parts, include_deprecated):
            continue
        raw = zf.read(info)
        upstream = "/".join(parts)
        docs = load_yaml_docs(raw, upstream)
        doc = next((d for d in docs if isinstance(d, dict) and d.get("title")), None)

        platform, sub = platform_for(parts, doc or {})
        ruleset = ruleset_name(parts[0])
        dest = rules_dir / platform / sub / parts[-1]
        if dest.exists():  # same file name from another rule set -> keep both
            dest = dest.with_name(f"{ruleset}__{parts[-1]}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        count += 1

        if doc:
            entries.append(build_entry(doc, dest, rules_dir.parent, platform, ruleset, upstream))
    return entries, count


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
        "by_platform": Counter(e["platform"] for e in entries),
        "by_ruleset": Counter(e["ruleset"] for e in entries),
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
    ap = argparse.ArgumentParser(description="Fetch all Sigma rules from SigmaHQ, sorted by platform.")
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
            and previous.get("include_deprecated") == args.include_deprecated \
            and previous.get("layout") == "platform":
        print(f"Already up to date with {args.repo}@{sha[:10]}. Nothing to do.")
        return 0

    zf = download_zip(s, args.repo, sha)
    entries, file_count = extract_rules(zf, out / "rules", args.include_deprecated)
    print(f"Extracted {file_count} rule files into platform folders")
    write_index(entries, out)

    meta = {
        "upstream_repo": args.repo,
        "upstream_branch": args.branch,
        "upstream_commit": sha,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "layout": "platform",
        "rule_files": file_count,
        "indexed_rules": len(entries),
        "rules_per_platform": dict(Counter(e["platform"] for e in entries).most_common()),
        "include_deprecated": args.include_deprecated,
        "license": "Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License",
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Indexed {len(entries)} rules from {args.repo}@{sha[:10]} into {out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
