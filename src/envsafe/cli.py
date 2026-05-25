"""CLI entry point for envsafe."""

from pathlib import Path
from typing import Annotated

import typer

from envsafe import __version__

app = typer.Typer(
    name="envsafe",
    help="Security audit CLI for environment variables and configuration files.",
    add_completion=False,
)

_SCANNER_MAP = {
    "secrets": "envsafe.scanners.secrets.SecretScanner",
    "gitignore": "envsafe.scanners.gitignore.GitignoreScanner",
    "docker": "envsafe.scanners.docker.DockerScanner",
    "weak": "envsafe.scanners.weak_credentials.WeakCredentialScanner",
    "env-example": "envsafe.scanners.env_example.EnvExampleScanner",
}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"envsafe {__version__}")
        raise typer.Exit()


def _load_scanner(dotted: str):
    module_path, cls_name = dotted.rsplit(".", 1)
    import importlib

    mod = importlib.import_module(module_path)
    return getattr(mod, cls_name)()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """envsafe — security scanner for environment variables and config files."""


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Directory to scan.")] = Path("."),
    json_output: Annotated[bool, typer.Option("--json", help="Output results as JSON.")] = False,
    strict: Annotated[
        bool, typer.Option("--strict", help="Exit with code 1 on any CRITICAL finding.")
    ] = False,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Paths to exclude (glob patterns)."),
    ] = None,
    rules: Annotated[
        str | None,
        typer.Option(
            "--rules",
            help="Comma-separated scanners to run (secrets,gitignore,docker,weak,env-example).",
        ),
    ] = None,
) -> None:
    """Scan a directory for security issues in environment variables and config files."""
    from envsafe.models import Severity
    from envsafe.reporter import print_json_report, print_text_report
    from envsafe.scanner import Scanner, _default_scanners

    typer.echo(f"Scanning {path}...")

    if rules:
        names = [r.strip() for r in rules.split(",")]
        unknown = [n for n in names if n not in _SCANNER_MAP]
        if unknown:
            valid = ", ".join(_SCANNER_MAP)
            typer.echo(f"Unknown scanner(s): {', '.join(unknown)}. Valid: {valid}", err=True)
            raise typer.Exit(code=2)
        scanners = [_load_scanner(_SCANNER_MAP[n]) for n in names]
    else:
        scanners = _default_scanners()

    scanner = Scanner(scanners=scanners)
    result = scanner.run(path.resolve())

    if exclude:
        import fnmatch

        result.findings = [
            f
            for f in result.findings
            if not any(fnmatch.fnmatch(f.file_path, pat) for pat in exclude)
        ]

    if json_output:
        print_json_report(result)
    else:
        print_text_report(result)

    has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
    has_warning_plus = any(
        f.severity in (Severity.CRITICAL, Severity.WARNING) for f in result.findings
    )

    if strict and has_critical:
        raise typer.Exit(code=1)
    elif not strict and has_warning_plus:
        raise typer.Exit(code=1)
