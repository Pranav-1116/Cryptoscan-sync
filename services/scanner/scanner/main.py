"""CryptoScan Static Java Scanner CLI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
import structlog

from scanner.core.scanner import Scanner
from scanner.git.git_client import GitClient
from scanner.output.json_writer import JsonWriter

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if sys.stdout.isatty() else structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()


@click.group()
@click.version_option("0.1.0", prog_name="cryptoscan-scanner")
def cli():
    """Detect cryptographic API usage in Java source."""


@cli.command()
@click.option("--source", "-s", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--repo", "-r", type=str)
@click.option("--branch", "-b", type=str, default=None)
@click.option("--commit", "-c", type=str, default=None)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=Path("./scan-output"))
@click.option("--exclude-tests/--include-tests", default=False)
@click.option("--scan-id", type=str, default=None)
def scan(source, repo, branch, commit, output, exclude_tests, scan_id):
    """Scan Java source for cryptographic API usage."""
    if not source and not repo:
        click.echo("Error: Must provide either --source or --repo", err=True)
        sys.exit(1)
    if source and repo:
        click.echo("Error: Cannot use both --source and --repo", err=True)
        sys.exit(1)

    scanner = Scanner(exclude_test_dirs=exclude_tests)
    writer = JsonWriter()

    if source:
        result = scanner.scan(
            root_path=source,
            scan_id=scan_id,
            target_type="LOCAL_DIRECTORY",
            target_location=str(source),
        )
    else:
        git_client = GitClient()
        with git_client.temp_clone(repo, branch=branch) as (clone_path, git_meta):
            result = scanner.scan(
                root_path=clone_path,
                scan_id=scan_id,
                target_type="GIT_REPOSITORY",
                target_location=repo,
                target_commit=commit or git_meta.commit_hash,
                target_branch=git_meta.branch,
            )

    output_path = writer.write(result, output)
    stats = result.statistics
    click.echo(f"\nScan ID:        {result.scan_id}")
    click.echo(f"Files scanned:  {stats.files_scanned}")
    click.echo(f"Findings:       {stats.total_findings}")
    click.echo(f"  HIGH:         {stats.high_confidence}")
    click.echo(f"  MEDIUM:       {stats.medium_confidence}")
    click.echo(f"  LOW:          {stats.low_confidence}")
    click.echo(f"Output:         {output_path}\n")


if __name__ == "__main__":
    cli()
