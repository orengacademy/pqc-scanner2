"""renderers.pdf_executive — 4-6 page summary PDF for C-suite / auditors.

Sections: cover with headline numbers, framework compliance card,
top-10 critical/high findings, top remediation themes.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pqcscan import __version__
from pqcscan.store.repo import Repo


_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TOP_N = 10


def render_pdf_executive(repo: Repo, scan_id: int, output_path: Path) -> Path:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings = repo.list_findings(scan_id)
    framework_views = repo.list_framework_views(scan_id)

    class_counts: Counter[str] = Counter(f.classification for f in findings)
    sev_counts: Counter[str] = Counter(f.severity for f in findings)

    fw_summary: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for v in framework_views:
        fw_summary[v.framework][v.verdict] += 1

    severity_order = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}
    top_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity, 99),
                       0 if f.classification == "sangat-tinggi" else 1),
    )[:_TOP_N]

    # Top remediation themes — count probe_ids producing crit/high findings.
    crit_probes: Counter[str] = Counter(
        f.probe_id for f in findings if f.severity in {"crit", "high"}
    )

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True, lstrip_blocks=True,
    )
    template = env.get_template("pdf_executive.html")
    html_str = template.render(
        scan=scan, version=__version__,
        total_findings=len(findings),
        class_counts=dict(class_counts),
        sev_counts=dict(sev_counts),
        fw_summary={k: dict(v) for k, v in fw_summary.items()},
        top_findings=top_findings,
        crit_probes=crit_probes.most_common(5),
    )
    from weasyprint import HTML
    HTML(string=html_str).write_pdf(str(output_path))
    return output_path
