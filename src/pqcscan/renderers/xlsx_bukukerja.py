"""renderers.xlsx_bukukerja — Malaysian BUKUKERJA template Excel.

Sheets (dynamic):
  0_Inventory     — assets discovered (probe_id, type, name, location)
  1_SBOM          — SBOM-family findings (PURL, name, version, manager)
  2_CBOM          — CBOM-family crypto findings (algorithm, classification,
                    severity, location)
  3_RiskRegister  — per-finding risk register row (BUKUKERJA verdicts only)
  00_ReadMe       — workbook guide

Static reference sheets (5_RiskMatrix, 6_ProtocolCryptoMap) are out of
scope for the MVP — those are template artefacts maintained outside the
scanner.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

from pqcscan import __version__
from pqcscan.store.repo import Repo


_HEADER_FILL = PatternFill("solid", fgColor="14532D")  # dark green
_HEADER_FONT = Font(bold=True, color="FFFFFF")


def _style_headers(ws, ncols: int) -> None:
    for col in range(1, ncols + 1):
        cell = ws.cell(row=1, column=col)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(horizontal="left", vertical="center")
    ws.freeze_panes = "A2"


def render_xlsx_bukukerja(repo: Repo, scan_id: int, output_path: Path) -> Path:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    findings = repo.list_findings(scan_id)
    framework_views = repo.list_framework_views(scan_id, framework="bukukerja")
    bukukerja_by_finding: dict[int, list] = defaultdict(list)
    for v in framework_views:
        bukukerja_by_finding[v.finding_id].append(v)

    wb = Workbook()
    # Reuse the auto-created sheet for 0_Inventory.
    inv = wb.active
    inv.title = "0_Inventory"

    inv.append(["probe_id", "title", "algorithm", "classification", "evidence"])
    _style_headers(inv, 5)
    for f in findings:
        inv.append([
            f.probe_id, f.title, f.algorithm, f.classification,
            json.dumps(f.evidence, default=str),
        ])
    for col, w in {1: 28, 2: 60, 3: 18, 4: 14, 5: 50}.items():
        inv.column_dimensions[chr(64 + col)].width = w

    # 1_SBOM — sbom.* probes.
    sbom_ws = wb.create_sheet("1_SBOM")
    sbom_ws.append(["probe_id", "name", "version", "manager", "purl"])
    _style_headers(sbom_ws, 5)
    for f in findings:
        if not f.probe_id.startswith("sbom."):
            continue
        ev = f.evidence or {}
        sbom_ws.append([
            f.probe_id,
            ev.get("name", ""),
            ev.get("version", ""),
            ev.get("manager", ""),
            ev.get("purl", ""),
        ])
    for col, w in {1: 22, 2: 30, 3: 18, 4: 14, 5: 40}.items():
        sbom_ws.column_dimensions[chr(64 + col)].width = w

    # 2_CBOM — non-sbom, non-skipped findings (real crypto facts).
    cbom_ws = wb.create_sheet("2_CBOM")
    cbom_ws.append(["probe_id", "algorithm", "classification", "severity", "title", "location"])
    _style_headers(cbom_ws, 6)
    for f in findings:
        if f.probe_id.startswith("sbom.") or f.classification == "info":
            continue
        ev = f.evidence or {}
        location = (ev.get("path") or ev.get("endpoint")
                    or ev.get("device") or ev.get("dataset") or "")
        cbom_ws.append([
            f.probe_id, f.algorithm, f.classification, f.severity, f.title, location,
        ])
    for col, w in {1: 26, 2: 18, 3: 14, 4: 8, 5: 60, 6: 30}.items():
        cbom_ws.column_dimensions[chr(64 + col)].width = w

    # 3_RiskRegister — only BUKUKERJA verdicts.
    risk_ws = wb.create_sheet("3_RiskRegister")
    risk_ws.append([
        "finding_id", "algorithm", "classification",
        "bukukerja_clause", "verdict", "title",
    ])
    _style_headers(risk_ws, 6)
    for f in findings:
        verdicts = bukukerja_by_finding.get(f.id, [])
        if not verdicts:
            continue
        for v in verdicts:
            risk_ws.append([
                f.id, f.algorithm, f.classification,
                v.clause, v.verdict, f.title,
            ])
    for col, w in {1: 10, 2: 18, 3: 14, 4: 36, 5: 14, 6: 60}.items():
        risk_ws.column_dimensions[chr(64 + col)].width = w

    # 00_ReadMe.
    readme = wb.create_sheet("00_ReadMe", 0)  # insert as the first sheet
    readme.append([f"BUKUKERJA MIGRASI PQC 2025 — pqcscan v{__version__}"])
    readme.append([""])
    readme.append([f"Scan ID: {scan.id}"])
    readme.append([f"Started: {scan.started_at}"])
    readme.append([f"Mode: {scan.mode}"])
    readme.append([f"Total findings: {len(findings)}"])
    readme.append([f"BUKUKERJA verdicts: {len(framework_views)}"])
    readme.append([""])
    readme.append(["Sheets:"])
    readme.append(["  0_Inventory     - all findings, raw"])
    readme.append(["  1_SBOM          - sbom.* probe outputs (packages)"])
    readme.append(["  2_CBOM          - cryptographic findings (non-package)"])
    readme.append(["  3_RiskRegister  - BUKUKERJA risk-register entries only"])
    readme["A1"].font = Font(bold=True, size=14)

    wb.save(str(output_path))
    return output_path
