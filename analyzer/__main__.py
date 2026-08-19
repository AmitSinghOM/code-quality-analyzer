"""CLI entry point for the analyzer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import REPORT_SCHEMA_VERSION, RULESET_VERSION, __version__
from .anonymize import ANONYMIZED_PROJECT, ReportAnonymizer
from .baseline import (
    BaselineError,
    compare_findings,
    load_baseline,
    write_baseline,
)
from .complexity import ProjectComplexityAnalyzer
from .discovery import DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_FILES
from .offline import OfflineViolationError, enforce_offline
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from .rater import QualityRater, coverage_gap_ratio
from .scanner import CodeScanner

console = Console()

EXIT_OK = 0
EXIT_BELOW_THRESHOLD = 1
EXIT_NOTHING_ANALYZED = 2
EXIT_COVERAGE_GAP = 3
EXIT_FINDINGS = 4


@click.command()
@click.argument(
    "project_path",
    type=click.Path(
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
    ),
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed file matches",
)
@click.option(
    "--output-format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option(
    "--complexity",
    "-c",
    is_flag=True,
    help="Include experimental time/space complexity estimates",
)
@click.option(
    "--max-file-size",
    type=click.IntRange(min=1),
    default=DEFAULT_MAX_FILE_SIZE,
    show_default=True,
    help="Skip files larger than this many bytes",
)
@click.option(
    "--max-files",
    type=click.IntRange(min=1),
    default=DEFAULT_MAX_FILES,
    show_default=True,
    help="Stop after discovering this many Python files",
)
@click.option(
    "--redact-paths",
    is_flag=True,
    help="Report file names only, no directory structure",
)
@click.option(
    "--anonymize",
    is_flag=True,
    help="Remove project paths, metadata, and source identifiers from reports",
)
@click.option(
    "--offline",
    is_flag=True,
    help="Deny socket operations while analysis is running",
)
@click.option(
    "--fail-under",
    type=click.FloatRange(min=1.0, max=10.0),
    default=None,
    help="Exit non-zero if the rating is below this value (for CI)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["warning", "error"]),
    default=None,
    help="Exit 4 when a reported finding meets this severity",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        path_type=Path,
    ),
    default=None,
    help="Compare findings with a hashed baseline",
)
@click.option(
    "--write-baseline",
    "write_baseline_path",
    type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
    default=None,
    help="Write current finding fingerprints atomically",
)
@click.option(
    "--new-findings-only",
    is_flag=True,
    help="Report and gate only findings absent from --baseline",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Exit non-zero if any requested analysis is incomplete",
)
def main(
    project_path: str,
    verbose: bool,
    output_format: str,
    complexity: bool,
    max_file_size: int,
    max_files: int,
    redact_paths: bool,
    anonymize: bool,
    offline: bool,
    fail_under: float | None,
    fail_on: str | None,
    baseline_path: Path | None,
    write_baseline_path: Path | None,
    new_findings_only: bool,
    strict: bool,
):
    """Analyze a project without sending source outside the machine."""
    if new_findings_only and baseline_path is None:
        raise click.UsageError("--new-findings-only requires --baseline")

    try:
        with enforce_offline(offline):
            exit_code = _run_analysis(
                project_path=project_path,
                verbose=verbose,
                output_format=output_format,
                complexity=complexity,
                max_file_size=max_file_size,
                max_files=max_files,
                redact_paths=redact_paths,
                anonymize=anonymize,
                offline=offline,
                fail_under=fail_under,
                fail_on=fail_on,
                baseline_path=baseline_path,
                write_baseline_path=write_baseline_path,
                new_findings_only=new_findings_only,
                strict=strict,
            )
    except OfflineViolationError as error:
        raise click.ClickException(str(error)) from error

    sys.exit(exit_code)


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
    fail_under: float | None,
    fail_on: str | None,
    baseline_path: Path | None,
    write_baseline_path: Path | None,
    new_findings_only: bool,
    strict: bool,
) -> int:
    known_fingerprints = None
    if baseline_path is not None:
        try:
            known_fingerprints = load_baseline(baseline_path)
        except BaselineError as error:
            raise click.ClickException(str(error)) from error

    root = Path(project_path).resolve()
    anonymizer = ReportAnonymizer() if anonymize else None
    project_label = ANONYMIZED_PROJECT if anonymize else root.name
    internal_redaction = redact_paths and not anonymize

    if output_format == "text":
        console.print(f"\n[bold blue]Analyzing:[/bold blue] {project_label}\n")

    scanner = CodeScanner(
        root,
        max_file_size=max_file_size,
        max_files=max_files,
        redact_paths=internal_redaction,
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

    baseline_written = False
    if write_baseline_path is not None:
        try:
            write_baseline(write_baseline_path, scanner.findings)
        except BaselineError as error:
            raise click.ClickException(str(error)) from error
        baseline_written = True

    comparison = compare_findings(
        scanner.findings,
        known_fingerprints,
        written=baseline_written,
    )
    reported_findings = (
        list(comparison.new_findings)
        if new_findings_only
        else scanner.findings
    )
    baseline_summary = (
        comparison.as_dict()
        if baseline_path is not None or write_baseline_path is not None
        else None
    )

    complexity_data = None
    complexity_health = None
    if complexity:
        comp_analyzer = ProjectComplexityAnalyzer(
            root,
            max_file_size=max_file_size,
            max_files=max_files,
            redact_paths=internal_redaction,
        )
        comp_analyzer.analyze()
        complexity_data = comp_analyzer.get_summary()
        complexity_health = comp_analyzer.analysis_health()

    if output_format == "json":
        _emit_json(
            project_label,
            rating,
            rater,
            breakdown,
            dsa_found,
            design_found,
            scanner,
            scan_health,
            complexity_data,
            complexity_health,
            verbose,
            reported_findings,
            baseline_summary,
            anonymizer,
            offline,
            redact_paths,
        )
    else:
        _emit_text(
            rating,
            rater,
            breakdown,
            dsa_found,
            design_found,
            scanner,
            scan_health,
            complexity_data,
            verbose,
            reported_findings,
            baseline_summary,
            anonymizer,
            offline,
            redact_paths,
        )

    return _exit_code(
        scanner,
        rating,
        fail_under,
        strict,
        complexity_health=complexity_health,
        findings=reported_findings,
        fail_on=fail_on,
    )


def _exit_code(
    scanner: CodeScanner,
    rating: float,
    fail_under: float | None,
    strict: bool,
    complexity_health: dict | None = None,
    findings=None,
    fail_on: str | None = None,
) -> int:
    if scanner.files_scanned == 0:
        return EXIT_NOTHING_ANALYZED
    if strict and (
        scanner.has_coverage_gaps or _health_has_gaps(complexity_health)
    ):
        return EXIT_COVERAGE_GAP
    if fail_under is not None and rating < fail_under:
        return EXIT_BELOW_THRESHOLD
    if (
        fail_on is not None
        and _findings_reach_severity(findings or [], fail_on)
    ):
        return EXIT_FINDINGS
    return EXIT_OK


def _findings_reach_severity(findings, threshold: str) -> bool:
    severity_rank = {"warning": 1, "error": 2}
    minimum = severity_rank[threshold]
    return any(
        severity_rank.get(finding.severity, 0) >= minimum
        for finding in findings
    )


def _health_has_gaps(health: dict | None) -> bool:
    if not health:
        return False
    return bool(
        health.get("total_skipped", 0)
        or health.get("truncated", False)
        or health.get("failed_functions", 0)
    )


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
        entry = {
            "files": files,
            "file_count": len(files),
            "description": definitions[name]["description"],
        }
        if verbose:
            entry["evidence"] = [
                {"file": hit.file, "signals": hit.signals}
                for hit in evidence.get(name, [])
            ]
        payload[name] = entry
    return payload


def _finding_summary(findings):
    by_severity = {}
    by_category = {}
    for finding in findings:
        by_severity[finding.severity] = (
            by_severity.get(finding.severity, 0) + 1
        )
        by_category[finding.category] = (
            by_category.get(finding.category, 0) + 1
        )
    return {
        "total": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_category": dict(sorted(by_category.items())),
    }


def _privacy_payload(
    anonymizer: ReportAnonymizer | None,
    offline: bool,
    redact_paths: bool,
) -> dict:
    return {
        "anonymized": anonymizer is not None,
        "paths_redacted": bool(redact_paths or anonymizer is not None),
        "offline_enforced": offline,
    }


def _emit_json(
    project_label,
    rating,
    rater,
    breakdown,
    dsa_found,
    design_found,
    scanner,
    scan_health,
    complexity_data,
    complexity_health,
    verbose,
    reported_findings,
    baseline_summary,
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
        finding_payload = [
            anonymizer.finding(finding) for finding in reported_findings
        ]
        complexity_payload = anonymizer.complexity(complexity_data)

    output = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "analyzer_version": __version__,
        "ruleset_version": RULESET_VERSION,
        "project": project_label,
        "privacy": _privacy_payload(anonymizer, offline, redact_paths),
        "rating": rating,
        "label": rater.get_rating_label(rating),
        "breakdown": breakdown,
        "scan_health": health_payload,
        "package_intelligence": package_payload,
        "finding_summary": _finding_summary(reported_findings),
        "findings": finding_payload,
        "dsa_patterns": _pattern_payload(
            dsa_found,
            DSA_PATTERNS,
            scanner.dsa_evidence,
            verbose=verbose,
            anonymizer=anonymizer,
        ),
        "design_patterns": _pattern_payload(
            design_found,
            SYSTEM_DESIGN_PATTERNS,
            scanner.design_evidence,
            verbose=verbose,
            anonymizer=anonymizer,
        ),
    }
    if baseline_summary is not None:
        output["baseline"] = baseline_summary
    if complexity_payload:
        output["complexity"] = complexity_payload
    if complexity_health:
        output["complexity_health"] = (
            anonymizer.scan_health(complexity_health)
            if anonymizer is not None
            else complexity_health
        )
    click.echo(json.dumps(output, indent=2))


def _emit_text(
    rating,
    rater,
    breakdown,
    dsa_found,
    design_found,
    scanner,
    scan_health,
    complexity_data,
    verbose,
    reported_findings,
    baseline_summary,
    anonymizer,
    offline,
    redact_paths,
):
    privacy = _privacy_payload(anonymizer, offline, redact_paths)
    console.print(
        "[dim]Privacy: "
        f"anonymized={'yes' if privacy['anonymized'] else 'no'} | "
        f"paths redacted={'yes' if privacy['paths_redacted'] else 'no'} | "
        f"offline enforced={'yes' if privacy['offline_enforced'] else 'no'}"
        "[/dim]\n"
    )

    rating_color = "red" if rating < 4 else "yellow" if rating < 7 else "green"
    console.print(Panel(
        f"[bold {rating_color}]{rating}/10[/bold {rating_color}]\n"
        f"{rater.get_rating_label(rating)}",
        title="[bold]Quality Rating[/bold]",
        expand=False,
    ))

    console.print(
        f"\n[dim]Files scanned: {breakdown['files_scanned']} | "
        f"Lines: {breakdown['total_lines']}[/dim]"
    )
    console.print(
        f"[dim]DSA Score: {breakdown['dsa_score']} | "
        f"Design Score: {breakdown['design_score']} | "
        f"Maturity: {breakdown['maturity_score']}[/dim]\n"
    )

    for warning in breakdown.get("warnings", []):
        console.print(f"[yellow]![/yellow] {warning}")
    health_payload = (
        anonymizer.scan_health(scan_health)
        if anonymizer is not None
        else scan_health
    )
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
    _print_findings(finding_payload)
    _print_pattern_table(
        "DSA Patterns Detected",
        "cyan",
        dsa_found,
        DSA_PATTERNS,
        scanner.dsa_evidence,
        verbose,
        anonymizer,
    )
    _print_pattern_table(
        "System Design Patterns Detected",
        "magenta",
        design_found,
        SYSTEM_DESIGN_PATTERNS,
        scanner.design_evidence,
        verbose,
        anonymizer,
    )

    if not dsa_found and not design_found:
        console.print("[yellow]No significant patterns detected.[/yellow]")

    if complexity_data:
        projected_complexity = (
            anonymizer.complexity(complexity_data)
            if anonymizer is not None
            else complexity_data
        )
        _print_complexity(projected_complexity, verbose)


def _print_scan_health(scan_health, scanner):
    if scan_health["total_skipped"]:
        reasons = ", ".join(
            f"{reason}={count}"
            for reason, count in scan_health["skipped_by_reason"].items()
        )
        console.print(
            f"[yellow]![/yellow] {scan_health['total_skipped']} "
            f"file(s) skipped ({reasons})"
        )
    if scanner.unparsed_files:
        console.print(
            f"[yellow]![/yellow] {scanner.unparsed_files} file(s) "
            "could not be parsed; no semantic signals were used for "
            "those files"
        )
    if scan_health["truncated"]:
        console.print(
            "[yellow]![/yellow] File limit reached — results cover "
            "part of the project only (raise --max-files)"
        )


def _print_baseline_summary(summary):
    if summary is None:
        return
    console.print(Panel(
        f"[bold]Loaded:[/bold] {summary['loaded']}\n"
        f"[bold]Written:[/bold] {summary['written']}\n"
        f"[bold]Current findings:[/bold] {summary['current_findings']}\n"
        f"[bold]New findings:[/bold] {summary['new_findings']}",
        title="[bold]Finding Baseline[/bold]",
        expand=False,
    ))
    console.print()


def _print_package_intelligence(package):
    if isinstance(package, dict):
        if not package["pyproject_present"] and not package["module_count"]:
            return
        console.print(Panel(
            "[bold]Project metadata declared:[/bold] "
            f"{package['project_name_declared']}\n"
            f"[bold]Layout:[/bold] {package['layout']}\n"
            f"[bold]Modules:[/bold] {package['module_count']}\n"
            f"[bold]Declared dependencies:[/bold] "
            f"{package['dependency_count']}\n"
            f"[bold]Circular import groups:[/bold] "
            f"{package['circular_import_group_count']}",
            title="[bold]Package Intelligence (Anonymized)[/bold]",
            expand=False,
        ))
        console.print()
        return

    if not package.pyproject_present and not package.modules:
        return
    name = package.project_name or "not declared"
    source_roots = ", ".join(package.source_roots) or "none"
    console.print(Panel(
        f"[bold]Project:[/bold] {name}\n"
        f"[bold]Layout:[/bold] {package.layout} ({source_roots})\n"
        f"[bold]Modules:[/bold] {len(package.modules)}\n"
        f"[bold]Declared dependencies:[/bold] "
        f"{len(package.dependencies)}\n"
        f"[bold]Circular import groups:[/bold] "
        f"{len(package.circular_imports)}",
        title="[bold]Package Intelligence[/bold]",
        expand=False,
    ))
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
                f"{location['path']}:{location['line']}:{location['column']}",
                finding["message"],
                finding["remediation"],
            )
        else:
            location = finding.location
            row = (
                finding.rule_id,
                finding.severity,
                f"{location.path}:{location.line}:{location.column}",
                finding.message,
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
            definitions[pattern]["description"],
            str(len(files)),
        )
        if verbose:
            for hit in evidence.get(pattern, [])[:3]:
                if anonymizer is None:
                    detail = f"{hit.file} ({', '.join(hit.signals[:4])})"
                else:
                    detail = (
                        f"{anonymizer.file(hit.file)} "
                        f"({len(hit.signals)} signal(s) redacted)"
                    )
                table.add_row("", f"  └─ {detail}", "")
    console.print(table)
    console.print()


def _print_complexity(complexity_data, verbose):
    avg_confidence = complexity_data.get("average_confidence", 0)
    console.print(Panel(
        f"[bold]Functions analyzed:[/bold] "
        f"{complexity_data['total_functions']}\n"
        f"[bold]Avg confidence:[/bold] {avg_confidence * 100:.0f}%",
        title="[bold]Complexity Analysis[/bold]",
        expand=False,
    ))

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

    console.print(
        f"[bold yellow]! {high_count} high-complexity "
        "function(s):[/bold yellow]"
    )
    table = Table(show_header=True)
    table.add_column("Function", style="red")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Time")
    table.add_column("Space")
    table.add_column("Confidence")

    for function in complexity_data.get("high_complexity_functions", [])[:10]:
        table.add_row(
            function["name"],
            function["file"],
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
            console.print(
                f"\n[cyan]{function['name']}[/cyan] ({function['file']})"
            )
            for reason in function.get("reasoning", []):
                console.print(f"  • {reason}")


if __name__ == "__main__":
    main()
