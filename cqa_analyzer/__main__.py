"""CLI entry point for the analyzer."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import argparse
import os

from . import (
    REPORT_SCHEMA_VERSION,
    RULESET_VERSION,
    SCORING_POLICY_VERSION,
    __version__,
)
from .anonymize import ANONYMIZED_PROJECT, ReportAnonymizer
from .baseline import (
    BaselineError,
    compare_findings,
    load_baseline,
    write_baseline,
)
from .changed_lines import ChangedLinesError, load_changed_lines
from .cache import CacheError, CacheStore
from .config import ConfigError, load_config
from .discovery import DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_FILES
from .offline import OfflineViolationError, enforce_offline
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from .plugins import create_default_registry
from .rater import QualityRater, coverage_gap_ratio
from .reporters import AnalysisReport, SarifRun
from .scanner import CodeScanner
from .text_render import Panel, Table, escape, get_console

console = get_console()

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _safe(value: object) -> str:
    """Render source-derived text (paths, names, messages) inertly.

    Rich treats ``[...]`` as markup and raises on a mismatched closing tag,
    so a file named ``arr[/i].py`` used to crash the text reporter; C0
    control characters could garble the terminal. Both are attacker-
    controllable in a fork PR (staff review round 2, A2/D3).
    """
    return escape(_CONTROL_CHARS.sub("", str(value)))


EXIT_OK = 0
EXIT_BELOW_THRESHOLD = 1
EXIT_NOTHING_ANALYZED = 2
EXIT_COVERAGE_GAP = 3
EXIT_FINDINGS = 4
EXIT_SCORE_NOT_APPLICABLE = 5
EXIT_CONFIG_MISMATCH = 6


class CliError(Exception):
    """A fatal, expected error: printed as ``Error: <message>`` and exit 1.

    3.0 (docs/adr/004) replaced click with argparse. This class keeps the exit
    code and the message shape click's ``ClickException`` had, so gates and
    scripts that match on either keep working.
    """


def _existing_directory(value: str) -> str:
    path = Path(value)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Directory {value!r} does not exist.")
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"Directory {value!r} is a file.")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"Directory {value!r} is not readable.")
    return value


def _existing_file(value: str) -> Path:
    path = Path(value)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"File {value!r} does not exist.")
    if path.is_dir():
        raise argparse.ArgumentTypeError(f"File {value!r} is a directory.")
    return path


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"Invalid value: {value!r} is not a valid integer."
        ) from error
    if number < 1:
        raise argparse.ArgumentTypeError(f"Invalid value: {number} is not in the range x>=1.")
    return number


def _score(value: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"Invalid value: {value!r} is not a valid float."
        ) from error
    if not 1.0 <= number <= 10.0:
        raise argparse.ArgumentTypeError(
            f"Invalid value: {number} is not in the range 1.0<=x<=10.0."
        )
    return number


def _add_analysis_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("analysis")
    group.add_argument("--verbose", "-v", action="store_true", help="Show detailed file matches")
    group.add_argument(
        "--output-format",
        "-f",
        dest="output_format",
        default="text",
        help="Registered output format (default: text)",
    )
    group.add_argument(
        "--complexity",
        "-c",
        action="store_true",
        help="Include experimental time/space complexity estimates",
    )
    group.add_argument(
        "--max-file-size",
        type=_positive_int,
        default=DEFAULT_MAX_FILE_SIZE,
        help=f"Skip files larger than this many bytes (default: {DEFAULT_MAX_FILE_SIZE})",
    )
    group.add_argument(
        "--max-files",
        type=_positive_int,
        default=DEFAULT_MAX_FILES,
        help=f"Stop after discovering this many source files (default: {DEFAULT_MAX_FILES})",
    )
    group.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help="Cache bounded parse artifacts in this local directory",
    )


def _add_privacy_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("privacy")
    group.add_argument(
        "--redact-paths",
        action="store_true",
        help="Report file names only, no directory structure",
    )
    group.add_argument(
        "--anonymize",
        action="store_true",
        help="Remove project paths, metadata, and source identifiers from reports",
    )
    group.add_argument(
        "--offline",
        action="store_true",
        help="Deny socket operations while analysis is running",
    )


def _add_gate_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("gating (CI)")
    group.add_argument(
        "--fail-under",
        type=_score,
        default=None,
        help="Exit non-zero if the compatibility architecture signal score is "
        "below this value (for CI)",
    )
    group.add_argument(
        "--fail-on",
        choices=["warning", "error"],
        default=None,
        help="Exit 4 when a reported finding meets this severity",
    )
    group.add_argument(
        "--baseline",
        dest="baseline_path",
        type=_existing_file,
        default=None,
        help="Compare findings with a hashed baseline",
    )
    group.add_argument(
        "--write-baseline",
        dest="write_baseline_path",
        type=Path,
        default=None,
        help="Write current finding fingerprints atomically",
    )
    group.add_argument(
        "--new-findings-only",
        action="store_true",
        help="Report and gate only findings absent from --baseline",
    )
    group.add_argument(
        "--changed-lines-manifest",
        type=Path,
        default=None,
        help="Report and gate findings overlapping a bounded line manifest",
    )
    group.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any requested analysis is incomplete",
    )


def _add_config_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("configuration")
    group.add_argument(
        "--config",
        dest="config_path",
        type=Path,
        default=None,
        help="Use this configuration file and ignore the project's own "
        ".code-quality.toml (pin the gate outside the tree being gated)",
    )
    group.add_argument(
        "--no-project-config",
        action="store_true",
        help="Ignore the project's .code-quality.toml and run with defaults",
    )
    group.add_argument(
        "--expect-config-fingerprint",
        default=None,
        metavar="SHA256",
        help="Exit with code 6 unless the effective configuration fingerprint "
        "equals this value (detects a PR that edits the gate's configuration)",
    )


def build_parser() -> argparse.ArgumentParser:
    """The CLI contract. Flags, defaults and exit codes are unchanged from 2.x."""
    parser = argparse.ArgumentParser(
        prog="code-quality-analyzer",
        description="Analyze a project without sending source outside the machine.",
        # click never matched flag prefixes; argparse does by default, which would
        # let ``--off``/``--output-form`` work today and break the moment a flag
        # sharing that prefix is added (review 5, A5).
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"code-quality-analyzer, version {__version__}",
    )
    parser.add_argument("project_path", type=_existing_directory, metavar="PROJECT_PATH")
    for add in (
        _add_analysis_options,
        _add_privacy_options,
        _add_gate_options,
        _add_config_options,
    ):
        add(parser)
    return parser


def main(argv: list[str] | None = None) -> None:
    """Parse arguments, run the analysis, and exit with the gate's code."""
    parser = build_parser()
    options = parser.parse_args(argv)
    if options.new_findings_only and options.baseline_path is None:
        parser.error("--new-findings-only requires --baseline")
    if options.config_path is not None and options.no_project_config:
        parser.error("--config and --no-project-config are mutually exclusive")

    try:
        with enforce_offline(options.offline):
            exit_code = _run_analysis(
                project_path=options.project_path,
                verbose=options.verbose,
                output_format=options.output_format,
                complexity=options.complexity,
                max_file_size=options.max_file_size,
                max_files=options.max_files,
                redact_paths=options.redact_paths,
                anonymize=options.anonymize,
                offline=options.offline,
                cache_dir=options.cache_dir,
                fail_under=options.fail_under,
                fail_on=options.fail_on,
                baseline_path=options.baseline_path,
                write_baseline_path=options.write_baseline_path,
                new_findings_only=options.new_findings_only,
                changed_lines_manifest=options.changed_lines_manifest,
                strict=options.strict,
                config_path=options.config_path,
                no_project_config=options.no_project_config,
                expect_config_fingerprint=options.expect_config_fingerprint,
            )
    except UsageError as error:
        parser.error(str(error))
    except (OfflineViolationError, CliError) as error:
        sys.stderr.write(f"Error: {error}\n")
        sys.exit(1)

    sys.exit(exit_code)


class UsageError(Exception):
    """A usage problem detected after parsing (exit 2 through the parser)."""


def _run_analysis(
    *,
    project_path: str,
    verbose: bool,
    output_format: str,
    complexity: bool,
    max_file_size: int,
    max_files: int,
    redact_paths: bool,
    anonymize: bool,
    offline: bool,
    cache_dir: Path | None,
    fail_under: float | None,
    fail_on: str | None,
    baseline_path: Path | None,
    write_baseline_path: Path | None,
    new_findings_only: bool,
    changed_lines_manifest: Path | None,
    strict: bool,
    config_path: Path | None = None,
    no_project_config: bool = False,
    expect_config_fingerprint: str | None = None,
) -> int:
    root = Path(project_path).resolve()
    try:
        configuration = load_config(
            root,
            config_path=config_path,
            use_project_config=not no_project_config,
        )
    except ConfigError as error:
        raise CliError(str(error)) from error
    if (
        expect_config_fingerprint is not None
        and configuration.fingerprint != expect_config_fingerprint.strip().lower()
    ):
        # The gate's configuration is not what the workflow pinned. Say so
        # before analysing anything, with a code no other outcome uses.
        console.print(
            "[bold red]Configuration fingerprint mismatch:[/bold red] expected "
            f"{escape(expect_config_fingerprint)}, effective "
            f"{configuration.fingerprint}. The project's .code-quality.toml "
            "differs from the one this gate was pinned to."
        )
        return EXIT_CONFIG_MISMATCH

    changed_line_selection = None
    if changed_lines_manifest is not None:
        try:
            changed_line_selection = load_changed_lines(changed_lines_manifest)
        except ChangedLinesError as error:
            raise CliError(str(error)) from error

    known_fingerprints = None
    if baseline_path is not None:
        try:
            known_fingerprints = load_baseline(baseline_path)
        except BaselineError as error:
            raise CliError(str(error)) from error

    anonymizer = ReportAnonymizer() if anonymize else None
    project_label = ANONYMIZED_PROJECT if anonymize else root.name
    internal_redaction = redact_paths and not anonymize
    registry = create_default_registry()
    try:
        reporter = registry.negotiate_reporter(output_format)
    except LookupError as error:
        available = ", ".join(item["format_name"] for item in registry.capabilities()["reporters"])
        raise UsageError(
            f"Unknown output format {output_format!r}; choose from {available}"
        ) from error

    cache_store = None
    if cache_dir is not None:
        try:
            cache_store = CacheStore(cache_dir)
        except CacheError as error:
            raise CliError(str(error)) from error

    scanner = CodeScanner(
        root,
        max_file_size=max_file_size,
        max_files=max_files,
        redact_paths=internal_redaction,
        registry=registry,
        configuration=configuration,
        cache_store=cache_store,
    )
    dsa_found, design_found = scanner.scan()
    scan_health = scanner.scan_health()

    gap_ratio = coverage_gap_ratio(
        files_scanned=scanner.files_scanned,
        skipped=scan_health["total_skipped"],
        unparsed=scanner.unparsed_files,
    )
    rater = QualityRater(
        dsa_found,
        design_found,
        scanner.files_scanned,
        scanner.total_lines,
        coverage_gap_ratio=gap_ratio,
    )
    rating, breakdown = rater.calculate_rating()
    signal_scope = scanner.architecture_signal_scope()

    baseline_written = False
    if write_baseline_path is not None:
        try:
            write_baseline(write_baseline_path, scanner.findings)
        except BaselineError as error:
            raise CliError(str(error)) from error
        baseline_written = True

    comparison = compare_findings(
        scanner.findings,
        known_fingerprints,
        written=baseline_written,
    )
    baseline_selected_findings = (
        list(comparison.new_findings) if new_findings_only else scanner.findings
    )
    changed_lines_summary = None
    if changed_line_selection is None:
        reported_findings = baseline_selected_findings
    else:
        try:
            reported_findings = list(changed_line_selection.select(baseline_selected_findings))
        except ChangedLinesError as error:
            raise CliError(str(error)) from error
        changed_lines_summary = changed_line_selection.summary(
            input_findings=len(baseline_selected_findings),
            selected_findings=len(reported_findings),
        )
    baseline_summary = (
        comparison.as_dict()
        if baseline_path is not None or write_baseline_path is not None
        else None
    )

    complexity_data = None
    complexity_health = None
    if complexity:
        result = scanner.run_project_provider("python", "complexity")
        if result is not None:
            complexity_data = result.payload
            complexity_health = dict(result.health)

    scan_health = scanner.scan_health()
    analysis_health = scanner.analysis_authority()

    if output_format == "json":
        report = AnalysisReport(
            structured=_build_json_report(
                project_label,
                rating,
                signal_scope,
                rater,
                breakdown,
                dsa_found,
                design_found,
                scanner,
                scan_health,
                analysis_health,
                complexity_data,
                complexity_health,
                verbose,
                reported_findings,
                baseline_summary,
                changed_lines_summary,
                anonymizer,
                offline,
                redact_paths,
            )
        )
    elif output_format == "sarif":
        report = AnalysisReport(
            sarif=_build_sarif_run(
                scanner,
                analysis_health,
                reported_findings,
                baseline_summary,
                changed_lines_summary,
                anonymizer,
                offline,
                redact_paths,
                new_findings_only,
            )
        )
    else:
        with console.capture() as capture:
            _emit_text(
                project_label,
                rating,
                signal_scope,
                rater,
                breakdown,
                dsa_found,
                design_found,
                scanner,
                scan_health,
                analysis_health,
                complexity_data,
                verbose,
                reported_findings,
                baseline_summary,
                changed_lines_summary,
                anonymizer,
                offline,
                redact_paths,
            )
        report = AnalysisReport(text=capture.get())
    rendered = reporter.render(report).decode("utf-8")
    sys.stdout.write(rendered if rendered.endswith("\n") else rendered + "\n")

    return _exit_code(
        scanner,
        rating,
        signal_scope,
        fail_under,
        strict,
        complexity_health=complexity_health,
        findings=reported_findings,
        fail_on=fail_on,
    )


def _exit_code(
    scanner: CodeScanner,
    rating: float,
    signal_scope: dict,
    fail_under: float | None,
    strict: bool,
    complexity_health: dict | None = None,
    findings=None,
    fail_on: str | None = None,
) -> int:
    if scanner.discovery.source_candidates == 0:
        return EXIT_NOTHING_ANALYZED
    if scanner.files_successfully_analyzed == 0:
        return EXIT_COVERAGE_GAP
    if strict and (scanner.has_coverage_gaps or _health_has_gaps(complexity_health)):
        return EXIT_COVERAGE_GAP
    if fail_under is not None and not signal_scope["applicable"]:
        return EXIT_SCORE_NOT_APPLICABLE
    if fail_under is not None and rating < fail_under:
        return EXIT_BELOW_THRESHOLD
    if fail_on is not None and _findings_reach_severity(findings or [], fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def _findings_reach_severity(findings, threshold: str) -> bool:
    severity_rank = {"warning": 1, "error": 2}
    minimum = severity_rank[threshold]
    return any(severity_rank.get(finding.severity, 0) >= minimum for finding in findings)


def _health_has_gaps(health: dict | None) -> bool:
    if not health:
        return False
    return bool(
        health.get("total_skipped", 0)
        or health.get("truncated", False)
        or health.get("failed_functions", 0)
    )


def _signal_definitions(scanner, category: str, builtins: dict) -> dict:
    definitions = dict(builtins)
    for observation in scanner.signal_observations:
        if observation.category == category:
            definitions.setdefault(
                observation.signal_id,
                {"description": observation.description},
            )
    return definitions


def _pattern_payload(
    found,
    definitions,
    evidence,
    verbose: bool,
    anonymizer: ReportAnonymizer | None = None,
):
    if anonymizer is not None:
        return anonymizer.patterns(found, definitions, evidence, verbose)

    payload = {}
    for name, files in found.items():
        definition = definitions.get(name, {})
        entry = {
            "files": files,
            "file_count": len(files),
            "description": definition.get(
                "description",
                "Plugin-provided architecture signal.",
            ),
        }
        if verbose:
            entry["evidence"] = [
                {"file": hit.file, "signals": hit.signals} for hit in evidence.get(name, [])
            ]
        payload[name] = entry
    return payload


def _finding_summary(findings):
    by_severity = {}
    by_category = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
    return {
        "total": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_category": dict(sorted(by_category.items())),
    }


def _privacy_payload(
    anonymizer: ReportAnonymizer | None,
    offline: bool,
    redact_paths: bool,
    cache_enabled: bool,
) -> dict:
    return {
        "anonymized": anonymizer is not None,
        "paths_redacted": bool(redact_paths or anonymizer is not None),
        "offline_enforced": offline,
        "cache_enabled": cache_enabled,
    }


def _build_sarif_run(
    scanner,
    analysis_health,
    reported_findings,
    baseline_summary,
    changed_lines_summary,
    anonymizer,
    offline,
    redact_paths,
    new_findings_only,
) -> SarifRun:
    if anonymizer is None:
        findings = tuple(finding.as_dict() for finding in reported_findings)
    else:
        identities = sorted(
            {
                finding.location.identity_path or finding.location.path
                for finding in reported_findings
            }
        )
        for identity in identities:
            anonymizer.file(identity)
        findings = tuple(anonymizer.finding(finding) for finding in reported_findings)

    baseline_selection = {"newFindingsOnly": new_findings_only}
    if baseline_summary is not None:
        baseline_selection.update(baseline_summary)
    return SarifRun(
        analyzer_version=__version__,
        configuration_fingerprint=scanner.configuration.fingerprint,
        analysis_health=analysis_health,
        privacy=_privacy_payload(
            anonymizer,
            offline,
            redact_paths,
            scanner.cache_enabled,
        ),
        baseline_selection=baseline_selection,
        changed_line_selection=changed_lines_summary,
        findings=findings,
    )


def _project_analysis_payload(scanner, anonymized: bool) -> dict:
    payload = {}
    for (language_id, capability), result in sorted(scanner.project_results.items()):
        key = f"{language_id}:{capability}"
        entry = {"health": dict(result.health)}
        if not anonymized:
            serializer = getattr(result.payload, "as_dict", None)
            if callable(serializer):
                entry["result"] = serializer()
            elif isinstance(result.payload, dict):
                entry["result"] = result.payload
        payload[key] = entry
    return payload


def _build_json_report(
    project_label,
    rating,
    signal_scope,
    rater,
    breakdown,
    dsa_found,
    design_found,
    scanner,
    scan_health,
    analysis_health,
    complexity_data,
    complexity_health,
    verbose,
    reported_findings,
    baseline_summary,
    changed_lines_summary,
    anonymizer,
    offline,
    redact_paths,
):
    if anonymizer is None:
        health_payload = scan_health
        package_payload = scanner.package_intelligence.as_dict()
        finding_payload = [finding.as_dict() for finding in reported_findings]
        complexity_payload = complexity_data
    else:
        health_payload = anonymizer.scan_health(scan_health)
        package_payload = anonymizer.package(scanner.package_intelligence)
        finding_payload = [anonymizer.finding(finding) for finding in reported_findings]
        complexity_payload = anonymizer.complexity(complexity_data)

    score_applicable = signal_scope["applicable"]
    score_value = rating if score_applicable else None
    score_label = rater.get_rating_label(rating) if score_applicable else "Not applicable"
    output = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "analyzer_version": __version__,
        "ruleset_version": RULESET_VERSION,
        "scoring_policy_version": SCORING_POLICY_VERSION,
        "configuration_fingerprint": scanner.configuration.fingerprint,
        "language_adapters": scanner.registry.capabilities()["languages"],
        "project": project_label,
        "privacy": _privacy_payload(
            anonymizer,
            offline,
            redact_paths,
            scanner.cache_enabled,
        ),
        "architecture_signal_score": score_value,
        "architecture_signal_label": score_label,
        "architecture_signal_scope": signal_scope,
        "rating": score_value,
        "label": score_label,
        "breakdown": breakdown,
        "analysis_health": analysis_health,
        "scan_health": health_payload,
        "package_intelligence": package_payload,
        "project_analyses": _project_analysis_payload(
            scanner,
            anonymized=anonymizer is not None,
        ),
        "finding_summary": _finding_summary(reported_findings),
        "findings": finding_payload,
        "dsa_patterns": _pattern_payload(
            dsa_found,
            _signal_definitions(scanner, "architecture.dsa", DSA_PATTERNS),
            scanner.dsa_evidence,
            verbose=verbose,
            anonymizer=anonymizer,
        ),
        "design_patterns": _pattern_payload(
            design_found,
            _signal_definitions(
                scanner,
                "architecture.design",
                SYSTEM_DESIGN_PATTERNS,
            ),
            scanner.design_evidence,
            verbose=verbose,
            anonymizer=anonymizer,
        ),
    }
    if baseline_summary is not None:
        output["baseline"] = baseline_summary
    if changed_lines_summary is not None:
        output["changed_lines"] = changed_lines_summary
    if complexity_payload:
        output["complexity"] = complexity_payload
    if complexity_health:
        output["complexity_health"] = (
            anonymizer.scan_health(complexity_health)
            if anonymizer is not None
            else complexity_health
        )
    return output


def _emit_text(
    project_label,
    rating,
    signal_scope,
    rater,
    breakdown,
    dsa_found,
    design_found,
    scanner,
    scan_health,
    analysis_health,
    complexity_data,
    verbose,
    reported_findings,
    baseline_summary,
    changed_lines_summary,
    anonymizer,
    offline,
    redact_paths,
):
    console.print(f"\n[bold blue]Analyzing:[/bold blue] {_safe(project_label)}\n")
    privacy = _privacy_payload(
        anonymizer,
        offline,
        redact_paths,
        scanner.cache_enabled,
    )
    console.print(
        "[dim]Privacy: "
        f"anonymized={'yes' if privacy['anonymized'] else 'no'} | "
        f"paths redacted={'yes' if privacy['paths_redacted'] else 'no'} | "
        f"offline enforced={'yes' if privacy['offline_enforced'] else 'no'} | "
        f"cache enabled={'yes' if privacy['cache_enabled'] else 'no'}"
        "[/dim]\n"
    )

    console.print(f"[dim]Configuration: {scanner.configuration.fingerprint}[/dim]\n")

    authority_label = "yes" if analysis_health["authoritative"] else "no"
    complete_label = "yes" if analysis_health["complete"] else "no"
    console.print(
        "[dim]Analysis: "
        f"authoritative={authority_label} | "
        f"complete={complete_label} | "
        f"successful={analysis_health['files_successfully_analyzed']}/"
        f"{analysis_health['source_candidates']}[/dim]\n"
    )
    if analysis_health["reasons"]:
        console.print(
            "[yellow]![/yellow] Analysis is non-authoritative: "
            + ", ".join(analysis_health["reasons"])
        )

    if signal_scope["applicable"]:
        rating_color = "red" if rating < 4 else "yellow" if rating < 7 else "green"
        console.print(
            Panel(
                f"[bold {rating_color}]{rating}/10[/bold {rating_color}]\n"
                f"{rater.get_rating_label(rating)}",
                title="[bold]Architecture Signal Score[/bold]",
                expand=False,
            )
        )
    else:
        scope_languages = ", ".join(signal_scope["languages"])
        console.print(
            Panel(
                "[bold]Not applicable[/bold]\n"
                f"No source from a signal-capable language ({scope_languages}) "
                "was analyzed",
                title="[bold]Architecture Signal Score[/bold]",
                expand=False,
            )
        )

    languages = ", ".join(
        f"{language}={count}" for language, count in sorted(scanner.language_counts.items())
    )
    console.print(
        f"\n[dim]Files scanned: {breakdown['files_scanned']} | "
        f"Lines: {breakdown['total_lines']} | Languages: {languages}[/dim]"
    )
    console.print(
        f"[dim]DSA Score: {breakdown['dsa_score']} | "
        f"Design Score: {breakdown['design_score']} | "
        f"Maturity: {breakdown['maturity_score']}[/dim]\n"
    )

    for warning in breakdown.get("warnings", []):
        console.print(f"[yellow]![/yellow] {warning}")
    health_payload = anonymizer.scan_health(scan_health) if anonymizer is not None else scan_health
    _print_scan_health(health_payload, scanner)
    if breakdown.get("warnings") or scanner.has_coverage_gaps:
        console.print()

    package_payload = (
        anonymizer.package(scanner.package_intelligence)
        if anonymizer is not None
        else scanner.package_intelligence
    )
    finding_payload = (
        [anonymizer.finding(finding) for finding in reported_findings]
        if anonymizer is not None
        else reported_findings
    )
    _print_package_intelligence(package_payload)
    _print_baseline_summary(baseline_summary)
    _print_changed_lines_summary(changed_lines_summary)
    _print_findings(finding_payload)
    _print_pattern_table(
        "DSA Patterns Detected",
        "cyan",
        dsa_found,
        _signal_definitions(scanner, "architecture.dsa", DSA_PATTERNS),
        scanner.dsa_evidence,
        verbose,
        anonymizer,
    )
    _print_pattern_table(
        "System Design Patterns Detected",
        "magenta",
        design_found,
        _signal_definitions(
            scanner,
            "architecture.design",
            SYSTEM_DESIGN_PATTERNS,
        ),
        scanner.design_evidence,
        verbose,
        anonymizer,
    )

    if not dsa_found and not design_found:
        console.print("[yellow]No significant patterns detected.[/yellow]")

    if complexity_data:
        projected_complexity = (
            anonymizer.complexity(complexity_data) if anonymizer is not None else complexity_data
        )
        _print_complexity(projected_complexity, verbose)


def _print_scan_health(scan_health, scanner):
    if scan_health["total_skipped"]:
        reasons = ", ".join(
            f"{reason}={count}" for reason, count in scan_health["skipped_by_reason"].items()
        )
        console.print(
            f"[yellow]![/yellow] {scan_health['total_skipped']} "
            f"file(s) skipped ({_safe(reasons)})"
        )
    if scanner.unparsed_files:
        console.print(
            f"[yellow]![/yellow] {scanner.unparsed_files} file(s) "
            "could not be parsed; no semantic signals were used for "
            "those files"
        )
        examples = scan_health.get("unparsed_examples", [])
        for path in examples:
            console.print(f"    - {_safe(path)}")
        remaining = scanner.unparsed_files - len(examples)
        if remaining > 0:
            console.print(
                f"    ... and {remaining} more (see unparsed_files in " "the JSON report)"
            )
    if scan_health["truncated"]:
        console.print(
            "[yellow]![/yellow] File limit reached — results cover "
            "part of the project only (raise --max-files)"
        )
    _print_excluded_generated(scan_health)


def _print_excluded_generated(scan_health):
    excluded = scan_health.get("excluded_generated", {})
    if not excluded:
        return
    total = sum(excluded.values())
    reasons = ", ".join(f"{reason}={count}" for reason, count in excluded.items())
    console.print(
        f"[dim]i[/dim] {total} minified/bundled file(s) left out ({_safe(reasons)}); "
        "they do not affect authority"
    )
    for paths in scan_health.get("excluded_generated_examples", {}).values():
        for path in paths:
            console.print(f"    - {_safe(path)}")


def _print_baseline_summary(summary):
    if summary is None:
        return
    console.print(
        Panel(
            f"[bold]Loaded:[/bold] {summary['loaded']}\n"
            f"[bold]Written:[/bold] {summary['written']}\n"
            f"[bold]Current findings:[/bold] {summary['current_findings']}\n"
            f"[bold]New findings:[/bold] {summary['new_findings']}",
            title="[bold]Finding Baseline[/bold]",
            expand=False,
        )
    )
    console.print()


def _print_changed_lines_summary(summary):
    if summary is None:
        return
    console.print(
        Panel(
            f"[bold]Files:[/bold] {summary['file_count']}\n"
            f"[bold]Canonical ranges:[/bold] {summary['range_count']}\n"
            f"[bold]Input findings:[/bold] {summary['input_findings']}\n"
            f"[bold]Selected findings:[/bold] {summary['selected_findings']}",
            title="[bold]Changed-Line Selection[/bold]",
            expand=False,
        )
    )
    console.print()


def _print_package_intelligence(package):
    if isinstance(package, dict):
        if not package["pyproject_present"] and not package["module_count"]:
            return
        console.print(
            Panel(
                "[bold]Project metadata declared:[/bold] "
                f"{_safe(package['project_name_declared'])}\n"
                f"[bold]Layout:[/bold] {_safe(package['layout'])}\n"
                f"[bold]Modules:[/bold] {package['module_count']}\n"
                f"[bold]Declared dependencies:[/bold] "
                f"{package['dependency_count']}\n"
                f"[bold]Circular import groups:[/bold] "
                f"{package['circular_import_group_count']}",
                title="[bold]Package Intelligence (Anonymized)[/bold]",
                expand=False,
            )
        )
        console.print()
        return

    if not package.pyproject_present and not package.modules:
        return
    name = package.project_name or "not declared"
    source_roots = ", ".join(package.source_roots) or "none"
    console.print(
        Panel(
            f"[bold]Project:[/bold] {_safe(name)}\n"
            f"[bold]Layout:[/bold] {_safe(package.layout)} ({_safe(source_roots)})\n"
            f"[bold]Modules:[/bold] {len(package.modules)}\n"
            f"[bold]Declared dependencies:[/bold] "
            f"{len(package.dependencies)}\n"
            f"[bold]Circular import groups:[/bold] "
            f"{len(package.circular_imports)}",
            title="[bold]Package Intelligence[/bold]",
            expand=False,
        )
    )
    console.print()


def _print_findings(findings):
    if not findings:
        return
    table = Table(title="Actionable Findings", show_header=True)
    table.add_column("Rule", style="yellow")
    table.add_column("Severity")
    table.add_column("Location", style="cyan")
    table.add_column("Message")
    table.add_column("Remediation")

    for finding in findings:
        if isinstance(finding, dict):
            location = finding["location"]
            row = (
                finding["rule_id"],
                finding["severity"],
                f"{_safe(location['path'])}:{location['line']}:{location['column']}",
                _safe(finding["message"]),
                finding["remediation"],
            )
        else:
            location = finding.location
            row = (
                finding.rule_id,
                finding.severity,
                f"{_safe(location.path)}:{location.line}:{location.column}",
                _safe(finding.message),
                finding.remediation,
            )
        table.add_row(*row)
    console.print(table)
    console.print()


def _print_pattern_table(
    title,
    style,
    found,
    definitions,
    evidence,
    verbose,
    anonymizer=None,
):
    if not found:
        return
    table = Table(title=title, show_header=True)
    table.add_column("Pattern", style=style)
    table.add_column("Description")
    table.add_column("Files", justify="right")

    sorted_patterns = sorted(
        found.items(),
        key=lambda item: -len(item[1]),
    )
    for pattern, files in sorted_patterns:
        table.add_row(
            pattern,
            definitions.get(pattern, {}).get(
                "description",
                "Plugin-provided architecture signal.",
            ),
            str(len(files)),
        )
        if verbose:
            for hit in evidence.get(pattern, [])[:3]:
                if anonymizer is None:
                    detail = _safe(f"{hit.file} ({', '.join(hit.signals[:4])})")
                else:
                    detail = (
                        f"{anonymizer.file(hit.file)} " f"({len(hit.signals)} signal(s) redacted)"
                    )
                table.add_row("", f"  └─ {detail}", "")
    console.print(table)
    console.print()


def _print_complexity(complexity_data, verbose):
    avg_confidence = complexity_data.get("average_confidence", 0)
    console.print(
        Panel(
            f"[bold]Functions analyzed:[/bold] "
            f"{complexity_data['total_functions']}\n"
            f"[bold]Avg confidence:[/bold] {avg_confidence * 100:.0f}%",
            title="[bold]Complexity Analysis[/bold]",
            expand=False,
        )
    )

    for label, key, style in (
        (
            "Time Complexity Distribution",
            "time_complexity_distribution",
            "cyan",
        ),
        (
            "Space Complexity Distribution",
            "space_complexity_distribution",
            "magenta",
        ),
    ):
        distribution = complexity_data.get(key)
        if not distribution:
            continue
        table = Table(title=label, show_header=True)
        table.add_column("Complexity", style=style)
        table.add_column("Count", justify="right")
        for complexity_class, count in distribution.items():
            table.add_row(complexity_class, str(count))
        console.print(table)
        console.print()

    high_count = complexity_data.get("high_complexity_count", 0)
    if not high_count:
        return

    console.print(f"[bold yellow]! {high_count} high-complexity " "function(s):[/bold yellow]")
    table = Table(show_header=True)
    table.add_column("Function", style="red")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Time")
    table.add_column("Space")
    table.add_column("Confidence")

    for function in complexity_data.get("high_complexity_functions", [])[:10]:
        table.add_row(
            _safe(function["name"]),
            _safe(function["file"]),
            str(function["line"]),
            function["time"],
            function["space"],
            f"{function['confidence']:.0%}",
        )
    console.print(table)

    if verbose:
        console.print("\n[dim]Reasoning for high-complexity functions:[/dim]")
        high_complexity = complexity_data.get(
            "high_complexity_functions",
            [],
        )
        for function in high_complexity[:5]:
            console.print(f"\n[cyan]{function['name']}[/cyan] ({function['file']})")
            for reason in function.get("reasoning", []):
                console.print(f"  • {reason}")


if __name__ == "__main__":
    main()
