#!/usr/bin/env python3
"""
Convert Sigma rule detections into SIEM-style expressions, for example

    keywords:
      - 'stopping iptables'
      - 'stopping firewalld'
    condition: keywords

becomes

    containAny(command_line, 'stopping iptables', 'stopping firewalld')

Reads sigma/index.json (written by fetch_sigma_rules.py) and writes
sigma/expressions.json and sigma/expressions.csv.

Usage:
  python convert_expressions.py
  python convert_expressions.py --keyword-field message   # field used for keyword lists
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import re
import sys
from pathlib import Path

import yaml

# Sigma field name -> your SIEM field name. Anything not listed is converted to snake_case.
FIELD_MAP = {
    "CommandLine": "command_line",
    "ParentCommandLine": "parent_command_line",
    "Image": "process_path",
    "ParentImage": "parent_process_path",
    "OriginalFileName": "original_file_name",
    "TargetFilename": "file_path",
    "TargetObject": "registry_key",
    "Details": "registry_value",
    "User": "user",
    "DestinationIp": "dest_ip",
    "DestinationPort": "dest_port",
    "DestinationHostname": "dest_host",
    "SourceIp": "src_ip",
    "SourcePort": "src_port",
    "EventID": "event_id",
    "Hashes": "hashes",
}

# Sigma modifier -> function name. "Any" = at least one value matches, "All" = every value matches.
FUNC_ANY = {"contains": "containAny", "startswith": "startsWithAny", "endswith": "endsWithAny",
            "equals": "equalsAny", "re": "regexAny", "cidr": "cidrAny"}
FUNC_ALL = {"contains": "containAll", "startswith": "startsWithAll", "endswith": "endsWithAll",
            "equals": "equalsAll", "re": "regexAll", "cidr": "cidrAll"}
COMPARE = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
IGNORED_MODIFIERS = {"cased", "windash", "i", "m", "s"}  # accepted, no effect on the output


class Unsupported(Exception):
    pass


def snake(name: str) -> str:
    name = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name)
    return re.sub(r"[^A-Za-z0-9_.]+", "_", name).lower()


def field_name(sigma_field: str, keyword_field: str) -> str:
    if not sigma_field:
        return keyword_field
    return FIELD_MAP.get(sigma_field, snake(sigma_field))


def quote(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def rx_escape(text: str) -> str:
    """Escape only real regex metacharacters, so 'stopping iptables' stays readable."""
    return re.sub(r"([.^$*+?{}\[\]\\|()])", r"\\\1", text)


def split_wildcards(value) -> tuple[str, object]:
    """Plain Sigma values may use * wildcards: *x* = contains, *x = endswith, x* = startswith."""
    if not isinstance(value, str) or "*" not in value:
        return "equals", value
    inner = value.strip("*")
    if "*" in inner or "?" in inner:
        # wildcard in the middle -> express as regex
        rx = "^" + "".join(".*" if c == "*" else "." if c == "?" else rx_escape(c) for c in value) + "$"
        return "re", rx
    if value.startswith("*") and value.endswith("*"):
        return "contains", inner
    if value.startswith("*"):
        return "endswith", inner
    return "startswith", inner


def join(parts: list[str], op: str) -> str:
    parts = [p for p in parts if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return "(" + f" {op} ".join(parts) + ")"


def field_expr(key: str, values, keyword_field: str) -> str:
    field_part, *mods = key.split("|")
    field = field_name(field_part, keyword_field)
    mods = [m for m in mods if m not in IGNORED_MODIFIERS]
    match_all = "all" in mods
    mods = [m for m in mods if m != "all"]

    values = values if isinstance(values, list) else [values]

    if "exists" in mods:
        return f"exists({field})" if values and values[0] else f"not exists({field})"
    if any(v is None for v in values):
        rest = [v for v in values if v is not None]
        null_part = f"isNull({field})"
        return join([null_part, field_expr(key, rest, keyword_field) if rest else ""], "or")

    for m in mods:
        if m in COMPARE:
            return join([f"{field} {COMPARE[m]} {quote(v)}" for v in values], "or")

    known = set(FUNC_ANY) | {"base64", "base64offset", "wide", "utf16le", "utf16be", "utf16"}
    unknown = [m for m in mods if m not in known]
    if unknown or any(m in mods for m in ("base64", "base64offset", "wide", "utf16le", "utf16be", "utf16")):
        raise Unsupported(f"modifier {'|'.join(mods)} on {field_part}")

    funcs = FUNC_ALL if match_all else FUNC_ANY
    if mods:
        mod = mods[0]
        grouped = {mod: values}
    else:
        grouped: dict[str, list] = {}
        for v in values:
            m, cleaned = split_wildcards(v)
            grouped.setdefault(m, []).append(cleaned)

    exprs = [f"{funcs[m]}({field}, {', '.join(quote(v) for v in vals)})" for m, vals in grouped.items()]
    return join(exprs, "and" if match_all else "or")


def selection_expr(sel, keyword_field: str) -> str:
    if isinstance(sel, dict):
        return join([field_expr(k, v, keyword_field) for k, v in sel.items()], "and")
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            return join([selection_expr(x, keyword_field) for x in sel], "or")
        # keyword list: plain strings searched in the keyword field
        return field_expr("|contains", [x for x in sel if not isinstance(x, dict)], keyword_field)
    if isinstance(sel, (str, int)):
        return field_expr("|contains", [sel], keyword_field)
    raise Unsupported(f"selection type {type(sel).__name__}")


TOKEN = re.compile(r"\s*(?:(1 of|any of|all of)\s+([\w*]+)|(\()|(\))|\b(and|or|not)\b|([\w*]+))", re.I)


def condition_expr(condition: str, selections: dict[str, str]) -> str:
    out = []
    pos = 0
    condition = condition.strip()
    while pos < len(condition):
        m = TOKEN.match(condition, pos)
        if not m or m.end() == pos:
            raise Unsupported(f"condition syntax near '{condition[pos:]}'")
        pos = m.end()
        quant, target, lp, rp, op, name = m.groups()
        if quant:
            if target.lower() == "them":
                names = [n for n in selections if not n.startswith("_")]
            else:
                names = [n for n in selections if fnmatch.fnmatchcase(n, target)]
            if not names:
                raise Unsupported(f"no selection matches '{target}'")
            out.append(join([selections[n] for n in names], "and" if quant.lower() == "all of" else "or"))
        elif lp:
            out.append("(")
        elif rp:
            out.append(")")
        elif op:
            out.append(op.lower())
        else:
            if name not in selections:
                raise Unsupported(f"unknown selection '{name}'")
            out.append(selections[name])
    text = " ".join(out)
    return text.replace("( ", "(").replace(" )", ")")


def keyword_values(detection: dict) -> list[str]:
    """All plain keyword strings in the rule (list-of-strings selections)."""
    vals = []
    for name, sel in detection.items():
        if name == "condition":
            continue
        if isinstance(sel, list) and all(isinstance(x, (str, int)) for x in sel):
            vals.extend(str(x) for x in sel)
        elif isinstance(sel, str):
            vals.append(sel)
    return vals


def convert_rule(doc: dict, keyword_field: str) -> dict:
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        return {"expression": "", "keywords": [], "keywords_regex": "",
                "conversion": "skipped: no detection block (correlation rule?)"}
    keywords = keyword_values(detection)
    keywords_regex = "(?i)(" + "|".join(rx_escape(k) for k in keywords) + ")" if keywords else ""
    try:
        selections = {name: selection_expr(sel, keyword_field)
                      for name, sel in detection.items() if name not in ("condition", "timeframe")}
        conditions = detection.get("condition")
        conditions = conditions if isinstance(conditions, list) else [conditions]
        expression = join([condition_expr(str(c), selections) for c in conditions if c], "or")
        status = "ok"
    except Unsupported as exc:
        expression, status = "", f"unsupported: {exc}"
    return {"expression": expression, "keywords": keywords,
            "keywords_regex": keywords_regex, "conversion": status}


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert Sigma detections to containAny-style expressions.")
    ap.add_argument("--sigma-dir", default="sigma", help="folder written by fetch_sigma_rules.py")
    ap.add_argument("--keyword-field", default="command_line",
                    help="field used for keyword lists (default: command_line)")
    args = ap.parse_args()

    root = Path(args.sigma_dir)
    index_file = root / "index.json"
    if not index_file.exists():
        print(f"{index_file} not found - run fetch_sigma_rules.py first", file=sys.stderr)
        return 1

    results = []
    for entry in json.loads(index_file.read_text(encoding="utf-8")):
        path = root / entry["path"]  # index paths are relative to the sigma folder
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
            print(f"  ! {path}: {exc}", file=sys.stderr)
            continue
        doc = next((d for d in docs if isinstance(d, dict) and d.get("detection")), None) \
            or next((d for d in docs if isinstance(d, dict)), {})
        conv = convert_rule(doc, args.keyword_field)
        results.append({
            "id": entry.get("id", ""),
            "title": entry.get("title", ""),
            "platform": entry.get("platform", ""),
            "level": entry.get("level", ""),
            "status": entry.get("status", ""),
            "path": entry["path"],
            **conv,
        })

    (root / "expressions.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    with (root / "expressions.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "title", "platform", "level", "status", "expression",
                                          "keywords_regex", "conversion", "path"], extrasaction="ignore")
        w.writeheader()
        w.writerows(results)

    ok = sum(r["conversion"] == "ok" for r in results)
    print(f"Converted {ok}/{len(results)} rules -> {root}/expressions.json and expressions.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
