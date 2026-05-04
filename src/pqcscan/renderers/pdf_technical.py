"""renderers.pdf_technical — full technical PDF: every finding + framework verdicts.

Reads from the SQLite store (Repo). Renders Jinja2 → HTML → WeasyPrint → PDF.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pqcscan import __version__
from pqcscan.store.repo import Repo


_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_pdf_technical(
    repo: Repo, scan_id: int, output_path: Path,
) -> Path:
    """Render scan_id as a technical PDF; returns the output_path."""
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings = repo.list_findings(scan_id)
    framework_views = repo.list_framework_views(scan_id)

    # Group framework verdicts by finding_id for easy template lookup.
    verdicts_by_finding: dict[int, list[Any]] = defaultdict(list)
    for v in framework_views:
        verdicts_by_finding[v.finding_id].append(v)

    # Per-classification counts for the executive summary block.
    class_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        class_counts[f.classification] += 1

    # Per-framework summary (counts of each verdict per framework).
    fw_summary: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for v in framework_views:
        fw_summary[v.framework][v.verdict] += 1

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("pdf_technical.html")
    html_str = template.render(
        scan=scan,
        findings=findings,
        verdicts_by_finding=verdicts_by_finding,
        class_counts=dict(class_counts),
        fw_summary={k: dict(v) for k, v in fw_summary.items()},
        total_findings=len(findings),
        total_framework_views=len(framework_views),
        version=__version__,
    )

    # Lazy import: weasyprint pulls in cairo/pango at module load.
    from weasyprint import HTML
    HTML(string=html_str).write_pdf(str(output_path))
    return output_path
