from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--scan", "scan_id", type=int, required=True)
@click.option(
    "--format", "fmt", required=True,
    type=click.Choice(["cbom", "pdf-tech"], case_sensitive=False),
)
@click.option("-o", "--out", type=click.Path(path_type=Path), required=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def export_cmd(scan_id: int, fmt: str, out: Path, db: Path | None) -> None:
    """Export a scan in the chosen format."""
    repo = Repo(db or default_db_path())
    repo.init_schema()
    if repo.get_scan(scan_id) is None:
        click.echo(f"scan {scan_id} not found", err=True)
        sys.exit(3)

    if fmt.lower() == "cbom":
        # Lazy imports keep CLI startup snappy and let optional deps stay
        # optional even if a renderer's transitive deps fail to import.
        from pqcscan.cbom.builder import build_cbom
        doc = build_cbom(repo, scan_id)
        out.write_text(json.dumps(doc, indent=2))
        click.echo(f"wrote CycloneDX 1.6 CBOM -> {out}")
    elif fmt.lower() == "pdf-tech":
        from pqcscan.renderers.pdf_technical import render_pdf_technical
        render_pdf_technical(repo, scan_id, out)
        click.echo(f"wrote technical PDF -> {out}")
