"""
CryptoScan Static Java Scanner - CLI Entrypoint

Usage:
    cryptoscan-scanner scan --source /path/to/repo --output /path/to/output
    cryptoscan-scanner scan --repo https://github.com/org/repo --branch main
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
import structlog

from scanner.core.scanner import Scanner
from scanner.git.git_client import GitClient
from scanner.models.raw_finding import GitContext
from scanner.output.json_writer import JsonWriter

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if sys.stdout.isatty()
        else structlog.processors.JSONRenderer(),
    ]
)

logger = structlog.get_logger()


@click.group()
@click.version_option("0.1.0", prog_name="cryptoscan-scanner")
def cli():
    """CryptoScan Static Java Scanner - Detect cryptographic API usage in Java code."""
    pass


@cli.command()
@click.option(
    "--source", "-s",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Local directory to scan",
)
@click.option(
    "--repo", "-r",
    type=str,
    help="Git repository URL to clone and scan",
)
@click.option(
    "--branch", "-b",
    type=str,
    default=None,
    help="Git branch to scan (default: repository default branch)",
)
@click.option(
    "--commit", "-c",
    type=str,
    default=None,
    help="Git commit hash to scan",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=Path("./scan-output"),
    show_default=True,
    help="Output directory for scan results",
)
@click.option(
    "--exclude-tests/--include-tests",
    default=False,
    show_default=True,
    help="Exclude test directories from scan",
)
@click.option(
    "--scan-id",
    type=str,
    default=None,
    help="Pre-assigned scan ID (UUID v4)",
)
def scan(
    source: Optional[Path],
    repo: Optional[str],
    branch: Optional[str],
    commit: Optional[str],
    output: Path,
    exclude_tests: bool,
    scan_id: Optional[str],
):
    """Scan Java source code for cryptographic API usage."""

    if not source and not repo:
        click.echo("Error: Must provide either --source or --repo", err=True)
        sys.exit(1)

    if source and repo:
        click.echo("Error: Cannot use both --source and --repo", err=True)
        sys.exit(1)

    scanner = Scanner(exclude_test_dirs=exclude_tests)
    writer = JsonWriter()

    if source:
        # Local directory scan
        logger.info("starting_local_scan", path=str(source))
        result = scanner.scan(
            root_path=source,
            scan_id=scan_id,
            target_type="LOCAL_DIRECTORY",
            target_location=str(source),
        )

    else:
        # Git repository scan
        git_client = GitClient()
        logger.info("starting_git_scan", repo=repo, branch=branch)

        with git_client.temp_clone(repo, branch=branch) as (clone_path, git_meta):
            result = scanner.scan(
                root_path=clone_path,
                scan_id=scan_id,
                target_type="GIT_REPOSITORY",
                target_location=repo,
                target_commit=git_meta.commit_hash,
                target_branch=git_meta.branch,
            )

            # Enrich findings with Git context
            git_context = GitContext(
                commit_hash=git_meta.commit_hash,
                commit_author=git_meta.commit_author,
                commit_timestamp=git_meta.commit_timestamp,
                branch=git_meta.branch,
                repository_url=repo,
                commit_message=git_meta.commit_message,
            )
            for finding in result.findings:
                finding.git_context = git_context

    # Write output
    output_path = writer.write(result, output)

    # Print summary
    stats = result.statistics
    click.echo(f"\n{'='*60}")
    click.echo(f"CRYPTOSCAN SCAN COMPLETE")
    click.echo(f"{'='*60}")
    click.echo(f"Scan ID:         {result.scan_id}")
    click.echo(f"Files Scanned:   {stats.files_scanned}")
    click.echo(f"Files with Crypto: {stats.files_with_crypto}")
    click.echo(f"Total Findings:  {stats.total_findings}")
    click.echo(f"  HIGH confidence:   {stats.high_confidence}")
    click.echo(f"  MEDIUM confidence: {stats.medium_confidence}")
    click.echo(f"  LOW confidence:    {stats.low_confidence}")
    click.echo(f"Duration:        {stats.duration_seconds:.2f}s")
    click.echo(f"Output:          {output_path}")
    click.echo(f"{'='*60}\n")

    if result.parse_errors:
        click.echo(f"WARNING: {len(result.parse_errors)} files had parse errors", err=True)


if __name__ == "__main__":
    cli()