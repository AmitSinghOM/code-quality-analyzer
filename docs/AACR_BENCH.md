# AACR-Bench as an external calibration corpus

Status: harness available as `scripts/aacr_bench_slice.py` (a development
tool, not part of the published package). First measured datapoint below;
no headline number is quotable yet.

## Running the harness

```bash
.venv/bin/python scripts/aacr_bench_slice.py --language Python --limit 5
GITHUB_TOKEN=... .venv/bin/python scripts/aacr_bench_slice.py --all --output slice.json
```

Development tool only: it downloads the dataset and GitHub tarballs (cached
under `~/.cache/cqa-aacr-bench`), which the analyzer itself never does.
Tarballs above `--max-tarball-mb` (default 150) are skipped and listed, never
partially processed. Smallest PRs run first. Unauthenticated GitHub allows 60
tarball requests an hour; set `GITHUB_TOKEN` for a full run. On a python.org
macOS build without a CA bundle, prefix `SSL_CERT_FILE=/etc/ssl/cert.pem`.

Matching: a finding is credited to an annotation when it is in the same
file, its rule belongs to the annotation's family, and the line spans
overlap within `--slack` lines (default 2). Left-side (pre-change)
annotations are excluded because the analyzer scans the post-change tree.
Findings in files with no annotation at all are ignored; findings in
annotated files that overlap nothing are reported as `unannotated` — they
are candidate true positives nobody wrote down, so the precision column is a
floor, not a measurement.

## First datapoint (2026-09-14, two smallest Python PRs)

| PR | Files scanned | Slice annotations | Matched | Unannotated hits in annotated files |
|----|---------------|-------------------|---------|--------------------------------------|
| infiniflow/ragflow#6691 | 902 | 1 (duplication) | 0 | 1 (PY-MAINT-001) |
| vllm-project/vllm#24425 | 1,888 | 1 (duplication) | 0 | 3 (PY-COR-002, PY-MAINT-001/002) |

Both annotations describe duplicated *logic* that the structural duplicate
detector (PY-DUP-001, normalised-AST identity) does not consider identical.
That is the expected gap between a reviewer's "this repeats that" and a
lexical tool's definition, and exactly the kind of result the slice exists
to surface. Two PRs prove the pipeline; they prove nothing about recall.

## What it is

[AACR-Bench](https://github.com/alibaba/aacr-bench) is Alibaba's public
benchmark for repository-level automatic code review, released alongside
[open-code-review](https://github.com/alibaba/open-code-review). It is
mirrored on Hugging Face as
[Alibaba-Aone/aacr-bench](https://huggingface.co/datasets/Alibaba-Aone/aacr-bench).

Verified from the public GitHub and Hugging Face APIs on 2026-09-14:

| Fact | Value | Source |
|------|-------|--------|
| License | Apache-2.0 (GitHub `LICENSE`, HF tag `license:apache-2.0`) | GitHub API, HF API |
| Gated | No | HF API |
| Ground truth file | `dataset/positive_samples.json`, 1,101,548 bytes | GitHub tree |
| Pull requests | 196 across 10 languages | file contents |
| Accepted annotations | 1,506 | file contents |

Publishing a derived comparison table is permitted under Apache-2.0 with
attribution.

## Schema

Top level: a JSON array of pull requests.

Per PR: `githubPrUrl`, `project_main_language`, `source_commit`,
`target_commit`, `change_line_count`, `category`, `comments[]`.

Per comment: `path`, `from_line`, `to_line`, `side`, `note`, `category`
(Code Defect 710 / Maintainability and Readability 626 / Performance 117 /
Security Vulnerability 53), `context` (Diff Level 754 / File Level 518 /
Repo Level 234), `is_ai_comment`, `source_model`.

The dataset carries **no diff or source text**. Reproducing a review means
fetching the post-change tree at `target_commit`:

```
https://api.github.com/repos/OWNER/REPO/tarball/<target_commit>
```

PRs by language: C++ 33, Java 30, TypeScript 29, Go 22, Python 21, C 19,
JavaScript 11, PHP 11, C# 10, Rust 10. Comments by language: TypeScript 305,
C++ 304, Java 213, Go 174, C 139, Python 114, JavaScript 112, Rust 59,
C# 45, PHP 41.

## Overlap slice (estimate)

A conservative keyword pass over the 1,506 `note` texts, mapping to the
analyzer's rule families, matched **261 distinct comments (17.3%)**. A
comment can hit more than one family.

| Rule family | Matches |
|-------------|---------|
| Unchecked assertion / non-null / unwrap (GO-COR-003, KT-COR-005, TS-COR-005, RS-COR-001) | 79 |
| Duplication (*-DUP-001) | 64 |
| Empty or broad catch, swallowed error (*-COR-001/003, PY-COR-002/003, GO-COR-001) | 42 |
| Resource without cleanup (PY-COR-006) | 39 |
| Complexity, long function, parameters (*-MAINT) | 24 |
| Unreachable code (PY-COR-004) | 12 |
| SQL assembled from runtime values (*-COR-002, PY-COR-007) | 6 |
| Blocking call in async (PY-COR-005, KT/CS/RS/TS-COR-00x) | 5 |
| Undeclared dependency or invalid manifest (*-PKG) | 3 |
| defer inside a loop (GO-COR-004) | 1 |

Matched comments by language: TypeScript 62, Go 56, Java 54, C++ 30, C 24,
Rust 16, Python 13, C# 8, JavaScript 8, PHP 4.

This is a keyword estimate, not a row-by-row human classification. It is an
upper bound on what a lexical tool could be credited with, and a lower bound
on nothing.

## Caveats before building a harness

1. **Annotations are a validated lower bound, not exhaustive.** A real
   analyzer hit that annotators did not write down scores as a false
   positive. Precision measured against AACR-Bench therefore understates
   true precision; report it as "precision against annotated set".
2. **Line alignment is loose.** Annotations are review comments, often on a
   symptom line, while findings anchor on the construct. Match on
   `(path, line-range overlap ±N)` and keep N explicit in the report.
3. **Out-of-scope languages.** JavaScript is analyzed by the TypeScript
   adapter; PHP has no adapter. 41 PHP comments are unreachable by design.
4. **Download cost.** Post-change tarballs range from tens of megabytes to
   over a gigabyte for monorepos (ClickHouse, elasticsearch, node). A harness
   must stream, cache by `target_commit`, and honour the unauthenticated
   GitHub rate limit (60 requests/hour) or use a token.

