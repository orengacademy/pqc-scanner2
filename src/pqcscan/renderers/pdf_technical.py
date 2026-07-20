"""renderers.pdf_technical — full technical report (HTML + optional PDF).

Bilingual (English / Bahasa Melayu). Reads from the SQLite store, renders
Jinja2 → HTML; `render_pdf_technical` additionally pipes the HTML through
WeasyPrint. The frozen binary ships without WeasyPrint, so the HTML path
(browser Print-to-PDF) is the universally-available one.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pqcscan.renderers._report_context import build_report_context
from pqcscan.store.repo import Repo

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _render_html(repo: Repo, scan_id: int, lang: str) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    ctx = build_report_context(repo, scan_id, lang=lang)
    return env.get_template("pdf_technical.html").render(**ctx)


def build_html_technical(repo: Repo, scan_id: int, lang: str = "en") -> str:
    """Render scan_id as a technical HTML report (no WeasyPrint needed)."""
    return _render_html(repo, scan_id, lang)


def render_pdf_technical(
    repo: Repo, scan_id: int, output_path: Path, lang: str = "en",
) -> Path:
    """Render scan_id as a technical PDF; returns the output_path."""
    html_str = _render_html(repo, scan_id, lang)
    try:
        from weasyprint import HTML
    except ImportError as e:
        raise ModuleNotFoundError(
            "PDF export requires weasyprint + cairo/pango runtime. "
            "Install with: pip install 'pqcscan[render]'. "
            "Frozen binaries currently do not bundle PDF support; "
            "use the HTML report or the XLSX / CBOM export instead.",
        ) from e
    HTML(string=html_str).write_pdf(str(output_path))
    return output_path
