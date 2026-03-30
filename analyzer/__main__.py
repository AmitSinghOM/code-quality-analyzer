"""CLI entry point for the analyzer."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .scanner import CodeScanner
from .rater import QualityRater
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS


console = Console()


@click.command()
@click.argument('project_path', type=click.Path(exists=True))
@click.option('--verbose', '-v', is_flag=True, help='Show detailed file matches')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
def main(project_path: str, verbose: bool, format: str):
    """Analyze a project for DSA and System Design patterns."""
    
    project_path = Path(project_path).resolve()
    
    if format == 'text':
        console.print(f"\n[bold blue]Analyzing:[/bold blue] {project_path}\n")
    
    # Scan project
    scanner = CodeScanner(project_path)
    dsa_found, design_found = scanner.scan()
    
    # Calculate rating
    rater = QualityRater(dsa_found, design_found, scanner.files_scanned, scanner.total_lines)
    rating, breakdown = rater.calculate_rating()
    
    if format == 'json':
        output = {
            "project": str(project_path),
            "rating": rating,
            "label": rater.get_rating_label(rating),
            "breakdown": breakdown,
            "dsa_patterns": {k: {"files": v, "description": DSA_PATTERNS[k]["description"]} 
                           for k, v in dsa_found.items()},
            "design_patterns": {k: {"files": v, "description": SYSTEM_DESIGN_PATTERNS[k]["description"]} 
                               for k, v in design_found.items()}
        }
        print(json.dumps(output, indent=2))
        return
    
    # Display rating
    rating_color = "red" if rating < 4 else "yellow" if rating < 7 else "green"
    console.print(Panel(
        f"[bold {rating_color}]{rating}/10[/bold {rating_color}]\n{rater.get_rating_label(rating)}",
        title="[bold]Quality Rating[/bold]",
        expand=False
    ))
    
    # Display breakdown
    console.print(f"\n[dim]Files scanned: {breakdown['files_scanned']} | Lines: {breakdown['total_lines']}[/dim]")
    console.print(f"[dim]DSA Score: {breakdown['dsa_score']} | Design Score: {breakdown['design_score']}[/dim]\n")
    
    # DSA patterns table
    if dsa_found:
        table = Table(title="DSA Patterns Detected", show_header=True)
        table.add_column("Pattern", style="cyan")
        table.add_column("Description")
        table.add_column("Files", justify="right")
        
        for pattern, files in dsa_found.items():
            desc = DSA_PATTERNS[pattern]["description"]
            table.add_row(pattern, desc, str(len(files)))
            if verbose:
                for f in files[:3]:
                    table.add_row("", f"  └─ {f}", "")
        
        console.print(table)
        console.print()
    
    # Design patterns table
    if design_found:
        table = Table(title="System Design Patterns Detected", show_header=True)
        table.add_column("Pattern", style="magenta")
        table.add_column("Description")
        table.add_column("Files", justify="right")
        
        for pattern, files in design_found.items():
            desc = SYSTEM_DESIGN_PATTERNS[pattern]["description"]
            table.add_row(pattern, desc, str(len(files)))
            if verbose:
                for f in files[:3]:
                    table.add_row("", f"  └─ {f}", "")
        
        console.print(table)
    
    if not dsa_found and not design_found:
        console.print("[yellow]No significant patterns detected.[/yellow]")


if __name__ == "__main__":
    main()
