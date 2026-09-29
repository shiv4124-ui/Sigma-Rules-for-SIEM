#!/usr/bin/env python3
"""
Fetch every Sigma rule from SigmaHQ/sigma, sort them into platform folders,
and build a searchable index.

Output layout:
  sigma/rules/windows/<category>/...      e.g. windows/process_creation/
  sigma/rules/linux/<category>/...
  sigma/rules/macos/<category>/...
  sigma/rules/cloud/<product>/...         e.g. cloud/aws/, cloud/azure/
  sigma/rules/network/<product>/...       e.g. network/zeek/, network/dns/
  sigma/rules/web/<category>/...          e.g. web/webserver/, web/proxy/
  sigma/rules/application/<product>/...   e.g. application/django/
  sigma/rules/other/...

Usage:
  python fetch_sigma_rules.py                  # fetch into ./sigma
  python fetch_sigma_rules.py --include-deprecated
  python fetch_sigma_rules.py --force          # re-download even if unchanged
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
ATTACK_ID = re.compile(r"^[tgs]\d{4}", re.IGNORECASE)

OS_PLATFORMS = {"windows", "linux", "macos"}
CLOUD_PRODUCTS = {
    "aws", "azure", "gcp", "m365", "okta", "onelogin", "google_workspace",
    "github", "bitbucket", "cisco_duo", "entra", "kubernetes",
}
NETWORK_PRODUCTS = {
    "zeek", "cisco", "fortios", "fortigate", "fortinet", "paloalto",
    "juniper", "huawei", "checkpoint", "sonicwall",
}
NETWORK_CATEGORIES = {"firewall", "dns"}
WEB_CATEGORIES = {"webserver", "proxy"}


def slug(value) -> str:
    text = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9_.-]+", "_", text).strip("_") or "general"


def classify(logsource: dict) -> tuple[str, str]:
    """Return (platform, subfolder) for a rule's logsource."""
    product = slug(logsource.get("product")) if logsource.get("product") else ""
    category = slug(logsource.get("category")) if logsource.get("category") else ""
    service = slug(logsource.get("service")) if logsource.get("service") else ""
    detail = category or service or "general"

    if product in OS_PLATFORMS:
        return product, detail
    if product in CLOUD_PRODUCTS:
        return "cloud", product
    if product in NETWORK_PRODUCTS:
        return "network", product
    if category in NETWORK_CATEGORIES:
        return "network", category
    if category in WEB_CATEGORIES or product in {"apache", "nginx", "iis"}:
        return "web", category or product
    if product:
        return "application", product
    return "other", detail


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
    if parts[0].startswith("rules"):
        return True
    return include_deprecated and parts[0] == "deprecated"


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def load_rule(raw: bytes, name: str) -> dict | None:
    try:
        docs = list(yaml.safe_load_all(raw.decode("utf-8")))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        print(f"  ! could not parse {name}: {exc}", file=sys.stderr)
        return None
    return next((d for d in docs if isinstance(d, dict) and d.get("title")), None)


def process(zf: zipfile.ZipFile, out: Path, include_deprecated: bool) -> list[dict]:
    rules_dir = out / "rules"
    if rules_dir.exists():
        shutil.rmtree(rules_dir)  # clean slate so rules removed upstream disappear here too

    entries, used = [], set()
    for info in zf.infolist():
        if info.is_dir():
            continue
        parts = info.filename.split("/")[1:]  # drop "sigma-<sha>/" root folder
        if not is_rule_path(parts, include_deprecated):
            continue
        raw = zf.read(info)
        doc = load_rule(raw, "/".join(parts))
        logsource = (doc or {}).get("logsource") or {}
        platform, sub = classify(logsource)

        dest = rules_dir / platform / sub / parts[-1]
        if dest in used:  # same filename from two rule sets -> keep both
            dest = dest.with_name(f"{dest.stem}_{slug(parts[0])}{dest.suffix}")
        used.add(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)

        if doc is None:
            continue
        entries.append({
            "id": doc.get("id", ""),
            "title": doc.get("title", ""),
            "platform": platform,
            "subfolder": sub,
            "ruleset": parts[0],
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
            "path": dest.relative_to(out).as_posix(),
            "upstream_path": "/".join(parts),
        })
    return entries


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
        "by_platform_subfolder": Counter(f'{e["platform"]}/{e["subfolder"]}' for e in entries),
        "by_ruleset": Counter(e["ruleset"] for e in entries),
        "by_level": Counter(e["level"] or "unset" for e in entries),
        "by_status": Counter(e["status"] or "unset" for e in entries),
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
    if (not args.force and previous.get("upstream_commit") == sha
            and previous.get("include_deprecated") == args.include_deprecated
            and previous.get("layout") == "platform"):
        print(f"Already up to date with {args.repo}@{sha[:10]}. Nothing to do.")
        return 0

    zf = download_zip(s, args.repo, sha)
    entries = process(zf, out, args.include_deprecated)
    write_index(entries, out)

    meta = {
        "upstream_repo": args.repo,
        "upstream_branch": args.branch,
        "upstream_commit": sha,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "indexed_rules": len(entries),
        "include_deprecated": args.include_deprecated,
        "layout": "platform",
        "license": "Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License",
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Sorted {len(entries)} rules from {args.repo}@{sha[:10]} into {out}/rules/<platform>/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
