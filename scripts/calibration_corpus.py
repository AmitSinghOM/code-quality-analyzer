# ruff: noqa: S603, S607, E501 -- dev tool; fixed argv, shells out to git on purpose
"""Cross-language fairness corpus (roadmap item 5).

Clones a fixed set of well-known open-source projects — the same two
domains in every supported language — scans each with the local analyzer,
and prints a Markdown comparison. Two projects in the same domain should
score similarly regardless of language; systematic gaps point at
under-anchored pattern specs, not at the projects.

Development tool only: it performs network clones, which the analyzer
itself never does. Run from the repository root:

    .venv/bin/python scripts/calibration_corpus.py [--keep] [--only LANG]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# (language, domain, GitHub "owner/repo", optional subdirectory to scan)
CORPUS = [
    ("python", "redis-client", "redis/redis-py", ""),
    ("go", "redis-client", "redis/go-redis", ""),
    ("typescript", "redis-client", "redis/ioredis", ""),
    ("java", "redis-client", "redis/jedis", ""),
    ("kotlin", "redis-client", "crackthecodeabhi/kreds", ""),
    ("csharp", "redis-client", "StackExchange/StackExchange.Redis", ""),
    ("c_cpp", "redis-client", "redis/hiredis", ""),
    ("python", "web-framework", "fastapi/fastapi", ""),
    ("go", "web-framework", "gin-gonic/gin", ""),
    ("typescript", "web-framework", "nestjs/nest", ""),
    ("java", "web-framework", "javalin/javalin", ""),
    ("kotlin", "web-framework", "ktorio/ktor", "ktor-server"),
    ("csharp", "web-framework", "FastEndpoints/FastEndpoints", ""),
    ("c_cpp", "web-framework", "drogonframework/drogon", ""),
    # Round 2: command-line tools — small, single-purpose, DSA-light by
    # nature; the domain most likely to expose anchor-depth differences.
    ("python", "cli-tool", "httpie/cli", ""),
    ("go", "cli-tool", "junegunn/fzf", ""),
    ("typescript", "cli-tool", "google/zx", ""),
    ("java", "cli-tool", "jbangdev/jbang", ""),
    ("kotlin", "cli-tool", "JakeWharton/diffuse", ""),
    ("csharp", "cli-tool", "dotnet-outdated/dotnet-outdated", ""),
    ("c_cpp", "cli-tool", "jqlang/jq", ""),
]


def scan(path: Path) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "cqa_analyzer", str(path), "--offline", "-f", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="keep clones")
    parser.add_argument("--only", default=None, help="restrict to one language")
    parser.add_argument("--domain", default=None, help="restrict to one domain")
    args = parser.parse_args()
    workdir = Path(tempfile.mkdtemp(prefix="cqa-corpus-"))
    rows = []
    try:
        for language, domain, slug, subdir in CORPUS:
            if (args.only and language != args.only) or (args.domain and domain != args.domain):
                continue
            target = workdir / slug.replace("/", "__")
            clone = subprocess.run(
                ["git", "clone", "-q", "--depth", "1", f"https://github.com/{slug}", str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            if clone.returncode != 0:
                print(f"clone failed: {slug}: {clone.stderr.strip()}", file=sys.stderr)
                continue
            sha = subprocess.run(
                ["git", "-C", str(target), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, check=False,
            ).stdout.strip()
            payload = scan(target / subdir if subdir else target)
            health = payload["analysis_health"]
            languages = payload["scan_health"]["languages"]
            breakdown = payload.get("breakdown", {})
            rows.append({
                "language": language,
                "domain": domain,
                "repo": slug,
                "sha": sha,
                "files": languages.get(language, 0),
                "lines": breakdown.get("total_lines"),
                "score": payload["architecture_signal_score"],
                "dsa_score": breakdown.get("dsa_score"),
                "design_score": breakdown.get("design_score"),
                "dsa": sorted(payload["dsa_patterns"]),
                "design": sorted(payload["design_patterns"]),
                "authoritative": health["authoritative"],
            })
            if not args.keep:
                shutil.rmtree(target, ignore_errors=True)
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"clones kept in {workdir}", file=sys.stderr)

    print("| language | domain | repo @ sha | files | lines | score | dsa | design | #dsa | #design | auth |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for row in sorted(rows, key=lambda r: (r["domain"], r["language"])):
        print(
            f"| {row['language']} | {row['domain']} | {row['repo']} @ {row['sha']} | "
            f"{row['files']} | {row['lines']} | {row['score']} | {row['dsa_score']} | "
            f"{row['design_score']} | {len(row['dsa'])} | {len(row['design'])} | "
            f"{'yes' if row['authoritative'] else 'no'} |"
        )
    print()
    for domain in sorted({r["domain"] for r in rows}):
        subset = [r for r in rows if r["domain"] == domain]
        patterns = sorted({p for r in subset for p in r["dsa"] + r["design"]})
        print(f"### {domain}: pattern matrix")
        print("| pattern | " + " | ".join(r["language"] for r in subset) + " |")
        print("|---|" + "---|" * len(subset))
        for pattern in patterns:
            marks = ["x" if pattern in r["dsa"] + r["design"] else "" for r in subset]
            print(f"| {pattern} | " + " | ".join(marks) + " |")
        print()
    # Machine-readable copy next to the Markdown, inside the repository
    # (never a predictable path in the shared temp dir — staff review A3).
    output = Path(__file__).resolve().parent.parent / "docs" / "calibration-latest.json"
    with output.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)
        handle.write("\n")
    print(f"rows written to {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
