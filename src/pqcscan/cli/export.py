from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from pqcscan.store.repo import Repo
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--scan", "scan_ref", required=True,
              help="Scan id, or 'fleet' for the latest scan of every enrolled host.")
@click.option(
    "--format", "fmt", required=True,
    type=click.Choice(
        ["cbom", "sarif", "pdf-tech", "pdf-exec", "xlsx-bukukerja", "xlsx-generic"],
        case_sensitive=False,
    ),
)
@click.option("-o", "--out", type=click.Path(path_type=Path), required=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option(
    "--lang",
    type=click.Choice(["ms", "en"], case_sensitive=False),
    default="ms",
    show_default=True,
    help="Output language for the PDF and BUKUKERJA XLSX reports.",
)
def export_cmd(
    scan_ref: str, fmt: str, out: Path, db: Path | None, lang: str,
) -> None:
    """Export a scan in the chosen format."""
    from pqcscan.cli.fleet import resolve_scan_ref
    repo = Repo(db or default_db_path())
    repo.init_schema()
    scan_id, temp = resolve_scan_ref(repo, scan_ref)
    try:
        if repo.get_scan(scan_id) is None:
            click.echo(f"scan {scan_id} not found", err=True)
            sys.exit(3)
        _export(repo, scan_id, fmt.lower(), lang, out)
    finally:
        if temp:
            repo.delete_scan(scan_id)


def _export(repo: Repo, scan_id: int, f: str, lang: str, out: Path) -> None:
    if f == "cbom":
        # Lazy imports keep CLI startup snappy and let optional deps stay
        # optional even if a renderer's transitive deps fail to import.
        from pqcscan.cbom.builder import build_cbom
        doc = build_cbom(repo, scan_id)
        out.write_text(json.dumps(doc, indent=2))
        click.echo(f"wrote CycloneDX 1.7 CBOM -> {out}")
    elif f == "sarif":
        from pqcscan.renderers.sarif import render_sarif
        render_sarif(repo, scan_id, out)
        click.echo(f"wrote SARIF 2.1.0 log -> {out}")
    elif f == "pdf-tech":
        from pqcscan.renderers.pdf_technical import render_pdf_technical
        render_pdf_technical(repo, scan_id, out, lang=lang.lower())
        click.echo(f"wrote technical PDF ({lang}) -> {out}")
    elif f == "pdf-exec":
        from pqcscan.renderers.pdf_executive import render_pdf_executive
        render_pdf_executive(repo, scan_id, out, lang=lang.lower())
        click.echo(f"wrote executive PDF ({lang}) -> {out}")
    elif f == "xlsx-bukukerja":
        from pqcscan.renderers.xlsx_bukukerja import render_xlsx_bukukerja
        render_xlsx_bukukerja(repo, scan_id, out, locale=lang.lower())
        click.echo(f"wrote BUKUKERJA XLSX ({lang}) -> {out}")
    elif f == "xlsx-generic":
        from pqcscan.renderers.xlsx_generic import render_xlsx_generic
        render_xlsx_generic(repo, scan_id, out)
        click.echo(f"wrote generic XLSX -> {out}")
