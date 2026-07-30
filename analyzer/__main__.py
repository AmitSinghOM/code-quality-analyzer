"""CLI entry point for the analyzer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .complexity import ProjectComplexityAnalyzer
from .discovery import DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_FILES
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from .rater import QualityRater, coverage_gap_ratio
from .scanner import CodeScanner

console = Console()

EXIT_OK = 0
EXIT_BELOW_THRESHOLD = 1
EXIT_NOTHING_ANALYZED = 2
EXIT_COVERAGE_GAP = 3


@click.command()
@click.argument(
    'project_path',
    type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True),
)
@click.option('--verbose', '-v', is_flag=True, help='Show detailed file matches')
@click.option('--output-format', '-f', 'output_format',
              type=click.Choice(['text', 'json']), default='text',
              help='Output format')
@click.option('--complexity', '-c', is_flag=True,
              help='Include time/space complexity analysis')
@click.option('--max-file-size', default=DEFAULT_MAX_FILE_SIZE, show_default=True,
              help='Skip files larger than this many bytes')
@click.option('--max-files', default=DEFAULT_MAX_FILES, show_default=True,
              help='Stop after discovering this many Python files')
@click.option('--redact-paths', is_flag=True,
              help='Report file names only, no directory structure')
@click.option('--fail-under', type=float, default=None,
              help='Exit non-zero if the rating is below this value (for CI)')
@click.option('--strict', is_flag=True,
              help='Exit non-zero if any discovered file could not be analyzed')
def main(project_path: str, verbose: bool, output_format: str, complexity: bool,
         max_file_size: int, max_files: int, redact_paths: bool,
         fail_under: float | None, strict: bool):
    """Analyze a project for DSA and System Design patterns."""

    root = Path(project_path).resolve()
    is_text = output_format == 'text'

    if is_text:
        shown_root = root.name if redact_paths else root
        console.print(f"\n[bold blue]Analyzing:[/bold blue] {shown_root}\n")

    scanner = CodeScanner(
        root,
        max_file_size=max_file_size,
        max_files=max_files,
        redact_paths=redact_paths,
    )
    dsa_found, design_found = scanner.scan()
    scan_health = scanner.scan_health()

    gap_ratio = coverage_gap_ratio(
        files_scanned=scanner.files_scanned,
        skipped=scan_health['total_skipped'],
        unparsed=scanner.unparsed_files,
    )

    rater = QualityRater(
        dsa_found, design_found,
        scanner.files_scanned, scanner.total_lines,
        coverage_gap_ratio=gap_ratio,
    )
    rating, breakdown = rater.calculate_rating()

    complexity_data = None
    complexity_health = None
    if complexity:
        comp_analyzer = ProjectComplexityAnalyzer(
            root,
            max_file_size=max_file_size,
            max_files=max_files,
            redact_paths=redact_paths,
        )
        comp_analyzer.analyze()
        complexity_data = comp_analyzer.get_summary()
        complexity_health = comp_analyzer.analysis_health()

    if output_format == 'json':
        _emit_json(root, rating, rater, breakdown, dsa_found, design_found,
                   scanner, scan_health, complexity_data, complexity_health,
                   redact_paths)
    else:
        _emit_text(rating, rater, breakdown, dsa_found, design_found,
                   scanner, scan_health, complexity_data, verbose)

    sys.exit(_exit_code(scanner, rating, fail_under, strict))


def _exit_code(scanner: CodeScanner, rating: float,
               fail_under: float | None, strict: bool) -> int:
    if scanner.files_scanned == 0:
        return EXIT_NOTHING_ANALYZED
    if strict and scanner.has_coverage_gaps:
        return EXIT_COVERAGE_GAP
    if fail_under is not None and rating < fail_under:
        return EXIT_BELOW_THRESHOLD
    return EXIT_OK


def _pattern_payload(found, definitions, evidence, verbose: bool):
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


def _emit_json(root, rating, rater, breakdown, dsa_found, design_found,
               scanner, scan_health, complexity_data, complexity_health,
               redact_paths):
    output = {
        "project": root.name if redact_paths else str(root),
        "rating": rating,
        "label": rater.get_rating_label(rating),
        "breakdown": breakdown,
        "scan_health": scan_health,
        "dsa_patterns": _pattern_payload(
            dsa_found, DSA_PATTERNS, scanner.dsa_evidence, verbose=True),
        "design_patterns": _pattern_payload(
            design_found, SYSTEM_DESIGN_PATTERNS, scanner.design_evidence,
            verbose=True),
    }
    if complexity_data:
        output["complexity"] = complexity_data
    if complexity_health:
        output["complexity_health"] = complexity_health
    click.echo(json.dumps(output, indent=2))


def _emit_text(rating, rater, breakdown, dsa_found, design_found,
               scanner, scan_health, complexity_data, verbose):
    rating_color = "red" if rating < 4 else "yellow" if rating < 7 else "green"
    console.print(Panel(
        f"[bold {rating_color}]{rating}/10[/bold {rating_color}]\n"
        f"{rater.get_rating_label(rating)}",
        title="[bold]Quality Rating[/bold]",
        expand=False
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

    for warning in breakdown.get('warnings', []):
        console.print(f"[yellow]![/yellow] {warning}")
    _print_scan_health(scan_health, scanner)
    if breakdown.get('warnings') or scanner.has_coverage_gaps:
        console.print()

    _print_pattern_table(
        "DSA Patterns Detected", "cyan", dsa_found, DSA_PATTERNS,
        scanner.dsa_evidence, verbose,
    )
    _print_pattern_table(
        "System Design Patterns Detected", "magenta", design_found,
        SYSTEM_DESIGN_PATTERNS, scanner.design_evidence, verbose,
    )

    if not dsa_found and not design_found:
        console.print("[yellow]No significant patterns detected.[/yellow]")

    if complexity_data:
        _print_complexity(complexity_data, verbose)


def _print_scan_health(scan_health, scanner):
    if scan_health['total_skipped']:
        reasons = ", ".join(
            f"{reason}={count}"
            for reason, count in scan_health['skipped_by_reason'].items()
        )
        console.print(
            f"[yellow]![/yellow] {scan_health['total_skipped']} file(s) skipped "
            f"({reasons})"
        )
    if scanner.unparsed_files:
        console.print(
            f"[yellow]![/yellow] {scanner.unparsed_files} file(s) could not be "
            f"parsed; only text signals were used for those"
        )
    if scan_health['truncated']:
        console.print(
            "[yellow]![/yellow] File limit reached — results cover part of the "
            "project only (raise --max-files)"
        )


def _print_pattern_table(title, style, found, definitions, evidence, verbose):
    if not found:
        return
    table = Table(title=title, show_header=True)
    table.add_column("Pattern", style=style)
    table.add_column("Description")
    table.add_column("Files", justify="right")

    for pattern, files in sorted(found.items(), key=lambda kv: -len(kv[1])):
        table.add_row(pattern, definitions[pattern]["description"], str(len(files)))
        if verbose:
            for hit in evidence.get(pattern, [])[:3]:
                signals = ", ".join(hit.signals[:4])
                table.add_row("", f"  └─ {hit.file} [dim]({signals})[/dim]", "")
    console.print(table)
    console.print()


def _print_complexity(complexity_data, verbose):
    avg_conf = complexity_data.get('average_confidence', 0)
    console.print(Panel(
        f"[bold]Functions analyzed:[/bold] {complexity_data['total_functions']}\n"
        f"[bold]Avg confidence:[/bold] {avg_conf * 100:.0f}%",
        title="[bold]Complexity Analysis[/bold]",
        expand=False
    ))

    for label, key, style in (
        ("Time Complexity Distribution", 'time_complexity_distribution', 'cyan'),
        ("Space Complexity Distribution", 'space_complexity_distribution', 'magenta'),
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

    high_count = complexity_data.get('high_complexity_count', 0)
    if not high_count:
        return

    console.print(f"[bold yellow]! {high_count} high-complexity function(s):[/bold yellow]")
    table = Table(show_header=True)
    table.add_column("Function", style="red")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Time")
    table.add_column("Space")
    table.add_column("Confidence")

    for func in complexity_data.get('high_complexity_functions', [])[:10]:
        table.add_row(
            func['name'], func['file'], str(func['line']),
            func['time'], func['space'], f"{func['confidence']:.0%}",
        )
    console.print(table)

    if verbose:
        console.print("\n[dim]Reasoning for high-complexity functions:[/dim]")
        for func in complexity_data.get('high_complexity_functions', [])[:5]:
            console.print(f"\n[cyan]{func['name']}[/cyan] ({func['file']})")
            for reason in func.get('reasoning', []):
                console.print(f"  • {reason}")


if __name__ == "__main__":
    main()
