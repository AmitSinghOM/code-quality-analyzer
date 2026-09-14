# ruff: noqa: S603, S607, E501 -- dev tool; fixed argv, network fetches on purpose
"""AACR-Bench overlap slice (docs/AACR_BENCH.md).

Measures the analyzer against the deterministic slice of Alibaba's AACR-Bench:
the human-verified review comments whose text names a defect class one of the
built-in rules can flag. For each selected pull request the script fetches the
post-change tree at ``target_commit``, runs the local analyzer, and matches
findings to annotations by path and line overlap.

Two honest numbers per rule family come out:

* **slice recall** -- annotated comments in the family that a finding overlapped;
* **precision against the annotated set** -- findings in annotated files that
  overlapped some annotation. Annotations are a lower bound, not an exhaustive
  list, so a real hit nobody wrote down counts here as unannotated. Treat this
  as a floor, and read ``unannotated_hits`` before drawing conclusions.

Development tool only: it downloads the dataset and GitHub tarballs, which the
analyzer itself never does. Run from the repository root:

    .venv/bin/python scripts/aacr_bench_slice.py --limit 5 --language Python
    GITHUB_TOKEN=... .venv/bin/python scripts/aacr_bench_slice.py --all --output slice.json

Requires network access, Git-free. Tarballs over ``--max-tarball-mb`` are
skipped and reported, never partially processed.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

DATASET_URL = (
    "https://raw.githubusercontent.com/alibaba/aacr-bench/main/dataset/positive_samples.json"
)
TARBALL_URL = "https://api.github.com/repos/{owner}/{repo}/tarball/{sha}"
DEFAULT_CACHE = Path.home() / ".cache" / "cqa-aacr-bench"

# AACR project_main_language -> analyzer adapter id (None: no adapter).
LANGUAGE_MAP = {
    "Python": "python",
    "Go": "go",
    "TypeScript": "typescript",
    "JavaScript": "typescript",
    "Java": "java",
    "Rust": "rust",
    "C#": "csharp",
    "C": "c_cpp",
    "C++": "c_cpp",
    "PHP": None,
}

# Rule family -> (regex over the annotation note, rule-id prefix matcher).
# Mirrors the keyword pass recorded in docs/AACR_BENCH.md; kept conservative.
FAMILIES: dict[str, tuple[str, str]] = {
    "sql-assembled": (
        r"sql injection|sql.*(concat|f-string|format|interpolat)|string.*sql|query.*(concat|format)",
        r"^(C|CS|GO|JAVA|KT|TS|RS)-COR-002$|^PY-COR-007$",
    ),
    "empty-or-broad-catch": (
        r"swallow|empty catch|catch(es|ing)? (all|everything|exception)|broad except|bare except|ignor(e|ed|es|ing) (the )?err|error (is )?(ignored|discarded|dropped|not checked|unchecked)|err != nil|silently",
        r"^(C|CS|JAVA|KT|TS)-COR-001$|^(C|CS|JAVA|KT)-COR-003$|^PY-COR-00[23]$|^GO-COR-001$",
    ),
    "blocking-in-async": (
        r"block(s|ing)? (the )?(event loop|async|thread)|synchronous.*async|time\.sleep|\.result\(\)|runBlocking|\.wait\(\)",
        r"^PY-COR-005$|^KT-COR-004$|^CS-COR-004$|^RS-COR-003$|^TS-COR-003$",
    ),
    "resource-leak": (
        r"leak|not closed|never closed|close\(\)|with statement|context manager|release[sd]? (the )?(file|connection|lock)",
        r"^PY-COR-006$",
    ),
    "mutable-default": (r"mutable default", r"^PY-COR-001$"),
    "unreachable": (r"unreachable|dead code|never (executed|reached)", r"^PY-COR-004$"),
    "unchecked-or-density": (
        r"unwrap\(\)|type assertion|\!\!|non-null assert|null pointer|nullpointer|npe\b|may be (null|nil|none)|nil (pointer|deref)|panic",
        r"^GO-COR-003$|^KT-COR-005$|^TS-COR-005$|^RS-COR-001$",
    ),
    "undeclared-dependency": (
        r"undeclared|not declared in|package\.json|go\.mod|cargo\.toml|pyproject|pom\.xml|missing (import|dependency|include)",
        r"-PKG-",
    ),
    "defer-in-loop": (r"defer.*loop|loop.*defer", r"^GO-COR-004$"),
    "complexity": (
        r"too (long|complex|many parameters)|cyclomatic|cognitive|nested|deeply nested|split (this|the) (function|method)",
        r"-MAINT-",
    ),
    "duplication": (r"duplicat", r"-DUP-"),
}
_FAMILY_NOTE = {name: re.compile(rx, re.IGNORECASE) for name, (rx, _) in FAMILIES.items()}
_FAMILY_RULE = {name: re.compile(rx) for name, (_, rx) in FAMILIES.items()}


def families_for_note(note: str) -> list[str]:
    return [name for name, rx in _FAMILY_NOTE.items() if rx.search(note or "")]


def family_for_rule(rule_id: str) -> str | None:
    for name, rx in _FAMILY_RULE.items():
        if rx.search(rule_id):
            return name
    return None


# --- fetching -------------------------------------------------------------------------


def _fetch(url: str, cache: Path, *, token: str | None, max_bytes: int) -> Path | None:
    """Download ``url`` into ``cache`` once. Returns None when over the size cap."""
    target = cache / hashlib.sha256(url.encode()).hexdigest()
    if target.exists():
        return target
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "cqa-aacr-bench-slice"})  # noqa: S310 - https enforced above
    if token and "api.github.com" in url:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - https only
        length = response.headers.get("Content-Length")
        if length and int(length) > max_bytes:
            return None
        buffer = io.BytesIO()
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            buffer.write(chunk)
            if buffer.tell() > max_bytes:
                return None
    cache.mkdir(parents=True, exist_ok=True)
    target.write_bytes(buffer.getvalue())
    return target


def _extract(tarball: Path, destination: Path) -> Path:
    """Safely extract a GitHub tarball; returns the single top-level directory."""
    with tarfile.open(tarball) as archive:
        if hasattr(tarfile, "data_filter"):
            archive.extractall(destination, filter="data")
        else:  # pragma: no cover - Python < 3.12
            archive.extractall(destination)  # noqa: S202
    children = [child for child in destination.iterdir() if child.is_dir()]
    if len(children) != 1:
        raise RuntimeError(f"unexpected tarball layout in {tarball}")
    return children[0]


def _parse_pr_url(url: str) -> tuple[str, str]:
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/pull/\d+", url)
    if not match:
        raise ValueError(f"unrecognised PR url: {url}")
    return match.group(1), match.group(2)


# --- matching -------------------------------------------------------------------------


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int, slack: int) -> bool:
    return not (a_end + slack < b_start or b_end + slack < a_start)


def _slice_annotations(pr: dict) -> list[tuple[str, int, int, list[str]]]:
    """Post-change-side comments whose note names a rule family."""
    annotations = []
    for comment in pr["comments"]:
        fams = families_for_note(comment.get("note", ""))
        if fams and comment.get("side", "right") != "left":
            annotations.append(
                (comment["path"], int(comment["from_line"]), int(comment["to_line"]), fams)
            )
    return annotations


def _finding_span(finding: dict) -> tuple[str, int, int]:
    location = finding["location"]
    start = int(location.get("line") or 0)
    return location.get("path", ""), start, int(location.get("end_line") or start)


def _matching_annotations(
    annotations: list[tuple[str, int, int, list[str]]],
    path: str,
    start: int,
    end: int,
    family: str,
    slack: int,
) -> list[int]:
    return [
        index
        for index, (a_path, a_start, a_end, fams) in enumerate(annotations)
        if a_path == path and family in fams and _overlaps(start, end, a_start, a_end, slack)
    ]


def _family_counts(
    annotations: list[tuple[str, int, int, list[str]]], matched: set[int]
) -> tuple[collections.Counter, collections.Counter]:
    all_families = collections.Counter(f for *_, fams in annotations for f in fams)
    matched_families = collections.Counter(
        f for i, (*_, fams) in enumerate(annotations) if i in matched for f in fams
    )
    return all_families, matched_families


def evaluate_pr(pr: dict, findings: list[dict], slack: int) -> dict:
    """Match one PR's findings to its slice annotations."""
    annotations = _slice_annotations(pr)
    annotated_paths = {path for path, *_ in annotations}
    matched_annotations: set[int] = set()
    credited: list[dict] = []
    unannotated: list[dict] = []
    for finding in findings:
        family = family_for_rule(finding["rule_id"])
        path, start, end = _finding_span(finding)
        if family is None or path not in annotated_paths:
            continue
        hits = _matching_annotations(annotations, path, start, end, family, slack)
        matched_annotations.update(hits)
        (credited if hits else unannotated).append(
            {"rule_id": finding["rule_id"], "path": path, "line": start, "family": family}
        )
    annotation_families, matched_families = _family_counts(annotations, matched_annotations)
    return {
        "slice_annotations": len(annotations),
        "matched_annotations": len(matched_annotations),
        "annotation_families": annotation_families,
        "matched_families": matched_families,
        "credited_findings": credited,
        "unannotated_findings": unannotated,
    }


def run_analyzer(root: Path, timeout: int) -> tuple[list[dict], dict]:
    """Run the local analyzer; return its findings and a scan-health subset.

    The health subset travels with each result so a 0% recall can be told
    apart from a scan that never reached the annotated files.
    """
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "cqa_analyzer",
            str(root),
            "--output-format",
            "json",
            "--offline",
            "--no-project-config",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if not completed.stdout.strip():
        raise RuntimeError(f"analyzer produced no report: {completed.stderr.strip()[:200]}")
    report = json.loads(completed.stdout)
    health = report.get("scan_health", {})
    return report["findings"], {
        "files_scanned": health.get("files_scanned"),
        "unparsed_files": health.get("unparsed_files"),
        "truncated": health.get("truncated"),
    }


# --- driver ---------------------------------------------------------------------------


def select_prs(dataset: list[dict], language: str | None, limit: int | None) -> list[dict]:
    chosen = []
    for pr in dataset:
        adapter = LANGUAGE_MAP.get(pr.get("project_main_language"))
        if adapter is None:
            continue
        if language and pr.get("project_main_language") != language:
            continue
        if any(families_for_note(c.get("note", "")) for c in pr["comments"]):
            chosen.append(pr)
    chosen.sort(key=lambda pr: (pr.get("change_line_count", 0), pr["githubPrUrl"]))  # small first
    return chosen[:limit] if limit else chosen


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--language", help="AACR project_main_language filter, e.g. Python")
    parser.add_argument(
        "--limit", type=int, default=5, help="PRs to evaluate (smallest first); --all overrides"
    )
    parser.add_argument("--all", action="store_true", help="evaluate every PR in the slice")
    parser.add_argument(
        "--slack", type=int, default=2, help="line slack when matching findings to annotations"
    )
    parser.add_argument("--max-tarball-mb", type=int, default=150)
    parser.add_argument(
        "--timeout", type=int, default=600, help="per-PR analyzer timeout in seconds"
    )
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path, help="write the full JSON result here")
    return parser


def _evaluate_one(
    pr: dict, args: argparse.Namespace, token: str | None
) -> tuple[dict | None, str | None]:
    """Fetch, scan and evaluate one PR. Returns (result, None) or (None, skip reason)."""
    owner, repo = _parse_pr_url(pr["githubPrUrl"])
    sha = pr["target_commit"]
    try:
        tarball = _fetch(
            TARBALL_URL.format(owner=owner, repo=repo, sha=sha),
            args.cache,
            token=token,
            max_bytes=args.max_tarball_mb * 1024 * 1024,
        )
    except urllib.error.HTTPError as error:
        return None, f"http {error.code}"
    if tarball is None:
        return None, f"tarball over {args.max_tarball_mb} MB"
    with tempfile.TemporaryDirectory(prefix="aacr-") as scratch:
        root = _extract(tarball, Path(scratch))
        try:
            findings, health = run_analyzer(root, args.timeout)
        except (subprocess.TimeoutExpired, RuntimeError) as error:
            return None, str(error)[:120]
    evaluation = evaluate_pr(pr, findings, args.slack)
    evaluation.update(
        pr=pr["githubPrUrl"],
        language=pr["project_main_language"],
        target_commit=sha,
        total_findings=len(findings),
        scan_health=health,
    )
    return evaluation, None


def _progress(pr: dict, evaluation: dict) -> str:
    owner, repo = _parse_pr_url(pr["githubPrUrl"])
    return (
        f"{owner}/{repo}@{pr['target_commit'][:8]} [{pr['project_main_language']}]: "
        f"annotations={evaluation['slice_annotations']} matched={evaluation['matched_annotations']} "
        f"credited={len(evaluation['credited_findings'])} "
        f"unannotated={len(evaluation['unannotated_findings'])} findings={evaluation['total_findings']}"
    )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN")

    dataset_path = _fetch(DATASET_URL, args.cache, token=None, max_bytes=50 * 1024 * 1024)
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    prs = select_prs(dataset, args.language, None if args.all else args.limit)
    print(f"dataset: {len(dataset)} PRs; slice candidates selected: {len(prs)}", file=sys.stderr)

    results = []
    skipped = []
    for pr in prs:
        evaluation, reason = _evaluate_one(pr, args, token)
        if evaluation is None:
            skipped.append({"pr": pr["githubPrUrl"], "reason": reason})
            print(f"skip {pr['githubPrUrl']}: {reason}", file=sys.stderr)
            continue
        results.append(evaluation)
        print(_progress(pr, evaluation), file=sys.stderr)

    summary = summarise(results)
    print(render_markdown(summary, results, skipped))
    if args.output:
        payload = {"summary": summary, "results": results, "skipped": skipped, "slack": args.slack}
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True, default=dict) + "\n")
    return 0


def summarise(results: list[dict]) -> dict:
    annotated: collections.Counter[str] = collections.Counter()
    matched: collections.Counter[str] = collections.Counter()
    credited: collections.Counter[str] = collections.Counter()
    unannotated: collections.Counter[str] = collections.Counter()
    for result in results:
        annotated.update(result["annotation_families"])
        matched.update(result["matched_families"])
        credited.update(f["family"] for f in result["credited_findings"])
        unannotated.update(f["family"] for f in result["unannotated_findings"])
    rows = {}
    for family in sorted(FAMILIES):
        a, m, c, u = annotated[family], matched[family], credited[family], unannotated[family]
        rows[family] = {
            "annotated": a,
            "matched": m,
            "slice_recall": (m / a) if a else None,
            "credited_findings": c,
            "unannotated_findings": u,
            "precision_vs_annotated": (c / (c + u)) if (c + u) else None,
        }
    return {"prs_evaluated": len(results), "families": rows}


def render_markdown(summary: dict, results: list[dict], skipped: list[dict]) -> str:
    def pct(value: float | None) -> str:
        return "n/a" if value is None else f"{value:.0%}"

    lines = [
        f"## AACR-Bench deterministic slice — {summary['prs_evaluated']} PRs evaluated, {len(skipped)} skipped",
        "",
        "| Family | Annotated | Matched | Slice recall | Credited | Unannotated | Precision vs annotated |",
        "|---|---|---|---|---|---|---|",
    ]
    for family, row in summary["families"].items():
        if (
            row["annotated"] == 0
            and row["credited_findings"] == 0
            and row["unannotated_findings"] == 0
        ):
            continue
        lines.append(
            f"| {family} | {row['annotated']} | {row['matched']} | {pct(row['slice_recall'])} | "
            f"{row['credited_findings']} | {row['unannotated_findings']} | {pct(row['precision_vs_annotated'])} |"
        )
    lines += [
        "",
        "Annotations are a validated lower bound, not an exhaustive list: every unannotated finding is a candidate",
        "true positive nobody wrote down, so the precision column is a floor. Review them before quoting it.",
    ]
    if skipped:
        lines += ["", "Skipped:"] + [f"- {item['pr']}: {item['reason']}" for item in skipped]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
