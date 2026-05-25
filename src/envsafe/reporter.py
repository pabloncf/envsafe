"""Formats and prints scan results."""

import json
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envsafe.models import ScanResult, Severity

console = Console()

_BANNER = """\
 ___ _ __ __   __ ___  __ _  __| | ___
/ _ \\ '_ \\ \\ \\ / / _ \\/ _` |/ _` |/ _ \\
|  __/ | | \\ V /  __/ (_| | (_| |  __/
 \\___|_| |_|\\_/ \\___|\\__,_|\\__,_|\\___|"""

_SEVERITY_LABEL = {
    Severity.CRITICAL: "[bold red]🔴 CRITICAL[/bold red]",
    Severity.WARNING: "[bold yellow]🟡 WARNING[/bold yellow]",
    Severity.INFO: "[bold blue]🔵 INFO[/bold blue]",
}


def print_text_report(result: ScanResult) -> None:
    """Print a human-readable Rich report to stdout.

    Args:
        result: The scan result to display.
    """
    console.print(Panel(Text(_BANNER, style="bold cyan"), expand=False))

    if not result.findings:
        console.print("\n[bold green]✅ No issues found! Your project looks secure.[/bold green]\n")
        return

    by_file: dict[str, list] = defaultdict(list)
    for finding in result.findings:
        by_file[finding.file_path].append(finding)

    for file_path, findings in sorted(by_file.items()):
        table = Table(title=f"[bold]{file_path}[/bold]", show_lines=True, expand=False)
        table.add_column("Severity", width=16)
        table.add_column("Rule", width=30)
        table.add_column("Line", width=6, justify="right")
        table.add_column("Message")

        for f in findings:
            table.add_row(
                _SEVERITY_LABEL[f.severity],
                f.rule_id,
                str(f.line_number) if f.line_number else "—",
                f.message,
            )

        console.print(table)

    critical = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    warnings = sum(1 for f in result.findings if f.severity == Severity.WARNING)
    info = sum(1 for f in result.findings if f.severity == Severity.INFO)
    console.print(
        f"\nFound [bold red]{critical} critical[/bold red], "
        f"[bold yellow]{warnings} warnings[/bold yellow], "
        f"[bold blue]{info} info[/bold blue]"
    )


def print_json_report(result: ScanResult) -> None:
    """Print findings as structured JSON to stdout.

    Args:
        result: The scan result to serialize.
    """
    data = {
        "scanned_files": result.scanned_files,
        "scan_duration": round(result.scan_duration, 3),
        "summary": {
            "critical": sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
            "warning": sum(1 for f in result.findings if f.severity == Severity.WARNING),
            "info": sum(1 for f in result.findings if f.severity == Severity.INFO),
        },
        "findings": [
            {
                "severity": f.severity.value,
                "rule_id": f.rule_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "message": f.message,
            }
            for f in result.findings
        ],
    }
    print(json.dumps(data, indent=2))
