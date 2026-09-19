# ruff: noqa: S603, S607 -- dev tool; fixed argv, shells out to git on purpose
"""Snapshot findings and scores across a corpus, then diff two snapshots.

The calibration corpus (``calibration_corpus.py``) answers "do scores stay
comparable across languages?". This tool answers the release question that
every new *rule* has to pass: "what does it fire on, in real code, and did
anything else move?" Run it on ``main`` and again on the release branch,
then ``--diff`` the two files. A rule ships only when every new hit has been
traced to source and the scores are unchanged (findings are reported, never
scored — the diff proves it).

Development tool only: ``--clone`` performs network clones, which the
analyzer itself never does.

    .venv/bin/python scripts/findings_snapshot.py snapshot --corpus-dir DIR \
        --out before.json [--clone] [--extra PATH ...]
    .venv/bin/python scripts/findings_snapshot.py diff before.json after.json \
        [--rules PREFIX ...]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from calibration_corpus import CORPUS  # noqa: E402

LOCATION_LIMIT = 4000
"""Per-project cap on stored finding locations, so a chatty rule cannot
turn the snapshot into a multi-megabyte file."""


def _scan(path: Path) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "cqa_analyzer", str(path), "--offline", "-f", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if not result.stdout.strip():
        raise RuntimeError(f"analyzer produced no output for {path}: {result.stderr[-400:]}")
    return json.loads(result.stdout)


def _project_row(name: str, path: Path) -> dict:
    payload = _scan(path)
    findings = payload.get("findings", [])
    by_rule = Counter(f["rule_id"] for f in findings)
    by_severity = Counter(f["severity"] for f in findings)
    locations = [
        {
            "rule_id": f["rule_id"],
            "severity": f["severity"],
            "path": f["location"]["path"],
            "line": f["location"]["line"],
            "message": f["message"],
        }
        for f in sorted(
            findings,
            key=lambda f: (f["rule_id"], f["location"]["path"], f["location"]["line"]),
        )
    ]
    return {
        "name": name,
        "score": payload["architecture_signal_score"],
        "ruleset_version": payload["ruleset_version"],
        "analyzer_version": payload["analyzer_version"],
        "finding_count": len(findings),
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "locations": locations[:LOCATION_LIMIT],
        "locations_truncated": len(locations) > LOCATION_LIMIT,
    }


def _ensure_clone(workdir: Path, slug: str, *, clone: bool) -> Path | None:
    target = workdir / slug.replace("/", "__")
    if target.exists():
        return target
    if not clone:
        print(f"missing clone (pass --clone): {slug}", file=sys.stderr)
        return None
    result = subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"https://github.com/{slug}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"clone failed: {slug}: {result.stderr.strip()}", file=sys.stderr)
        return None
    return target


def snapshot(args: argparse.Namespace) -> int:
    workdir = Path(args.corpus_dir)
    workdir.mkdir(parents=True, exist_ok=True)
    rows = []
    for _language, _domain, slug, subdir in CORPUS:
        if args.only and args.only not in slug:
            continue
        target = _ensure_clone(workdir, slug, clone=args.clone)
        if target is None:
            continue
        scan_root = target / subdir if subdir else target
        print(f"scanning {slug}", file=sys.stderr)
        rows.append(_project_row(slug, scan_root))
    for extra in args.extra:
        path = Path(extra).expanduser().resolve()
        print(f"scanning {path.name}", file=sys.stderr)
        rows.append(_project_row(path.name, path))
    payload = {"projects": rows}
    with Path(args.out).open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"{len(rows)} projects written to {args.out}", file=sys.stderr)
    return 0


def _load(path: str) -> dict[str, dict]:
    with Path(path).open(encoding="utf-8") as handle:
        return {row["name"]: row for row in json.load(handle)["projects"]}


def _matches(rule_id: str, fragments: list[str]) -> bool:
    return not fragments or any(f in rule_id for f in fragments)


def diff(args: argparse.Namespace) -> int:
    before = _load(args.before)
    after = _load(args.after)
    names = sorted(set(before) | set(after))
    print(
        "| project | score before | score after | findings before | findings after "
        "| rules added | rules removed |"
    )
    print("|---|---|---|---|---|---|---|")
    new_rule_hits: list[tuple[str, dict]] = []
    for name in names:
        b, a = before.get(name), after.get(name)
        if b is None or a is None:
            score_b = "-" if b is None else b["score"]
            score_a = "-" if a is None else a["score"]
            print(f"| {name} | {score_b} | {score_a} | | | only in one snapshot | |")
            continue
        added = sorted(set(a["by_rule"]) - set(b["by_rule"]))
        removed = sorted(set(b["by_rule"]) - set(a["by_rule"]))
        changed = {
            r: (b["by_rule"].get(r, 0), a["by_rule"].get(r, 0))
            for r in set(a["by_rule"]) | set(b["by_rule"])
            if b["by_rule"].get(r, 0) != a["by_rule"].get(r, 0)
            and r not in added
            and r not in removed
        }
        marker = "" if a["score"] == b["score"] else " **MOVED**"
        added_text = ", ".join(f"{r} ({a['by_rule'][r]})" for r in added) or "-"
        print(
            f"| {name} | {b['score']} | {a['score']}{marker} | {b['finding_count']} | "
            f"{a['finding_count']} | {added_text} | "
            f"{', '.join(removed) or '-'} |"
        )
        if changed:
            print(f"|  | | | | | changed counts: {changed} | |")
        for loc in a["locations"]:
            if loc["rule_id"] in added and _matches(loc["rule_id"], args.rules):
                new_rule_hits.append((name, loc))
    if new_rule_hits:
        print()
        print("### Every hit from a rule that did not exist before")
        print("| project | rule | severity | location | message |")
        print("|---|---|---|---|---|")
        for name, loc in new_rule_hits:
            print(
                f"| {name} | {loc['rule_id']} | {loc['severity']} | "
                f"{loc['path']}:{loc['line']} | {loc['message']} |"
            )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot", help="scan the corpus and write a snapshot")
    snap.add_argument(
        "--corpus-dir", required=True, help="directory holding (or receiving) the clones"
    )
    snap.add_argument("--out", required=True, help="snapshot JSON to write")
    snap.add_argument("--clone", action="store_true", help="clone missing corpus projects")
    snap.add_argument("--only", default=None, help="restrict to corpus slugs containing this text")
    snap.add_argument("--extra", nargs="*", default=[], help="additional local project paths")
    snap.set_defaults(func=snapshot)
    dif = sub.add_parser("diff", help="compare two snapshots")
    dif.add_argument("before")
    dif.add_argument("after")
    dif.add_argument(
        "--rules", nargs="*", default=[], help="rule-ID fragments (e.g. SEC) to list hit-by-hit"
    )
    dif.set_defaults(func=diff)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
