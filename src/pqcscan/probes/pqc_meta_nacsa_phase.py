"""pqc.meta.nacsa_phase — NACSA Arahan KE No. 9 Fasa state (Plan I.2 minimal).

Computes the current NACSA migration Fasa from today's date per Lampiran A
Sec C — Pelan Garis Masa Migrasi PQC:

  Fasa 1 — Persediaan (Assess)   : Jul-Dis 2025      (deadline 2025-12-31)
  Fasa 2 — Pemilihan  (Select)   : Jan-Jun 2026      (deadline 2026-06-30)
  Fasa 3 — Pengesahan (Validate) : Jul-Dis 2026      (deadline 2026-12-31)
  Fasa 4 — Pelaksanaan (Deploy)  : Jan-Jun 2027      (deadline 2027-06-30)
  Fasa 5 — Pemantauan (Monitor)  : Julai 2027 onwards

Emits a single Finding describing the current Fasa, days remaining until
the next deadline, and the next-fasa transition date.

Future Plan I.2 work (deferred): per-entity phase state in SQLite, CLI
commands `pqcscan phase status / advance`, UI /phases timeline view,
phase-driven cron scheduling.
"""
from __future__ import annotations

from datetime import date

from pqcscan.core.types import Classification, Finding, ProbeFamily, Severity
from pqcscan.probes._base import Emitter, Probe, ScanContext

_FASA_BOUNDARIES: tuple[tuple[date, str, str], ...] = (
    (date(2025, 12, 31), "Fasa 1", "Persediaan (Assess)"),
    (date(2026, 6, 30),  "Fasa 2", "Pemilihan (Select)"),
    (date(2026, 12, 31), "Fasa 3", "Pengesahan (Validate)"),
    (date(2027, 6, 30),  "Fasa 4", "Pelaksanaan (Deploy)"),
    (date(2099, 12, 31), "Fasa 5", "Pemantauan (Monitor)"),
)


def _current_fasa(today: date) -> tuple[str, str, date, int]:
    """Return (fasa_name, fasa_label, deadline, days_remaining)."""
    for deadline, name, label in _FASA_BOUNDARIES:
        if today <= deadline:
            return name, label, deadline, (deadline - today).days
    last = _FASA_BOUNDARIES[-1]
    return last[1], last[2], last[0], (last[0] - today).days


class PqcMetaNacsaPhase(Probe):
    id = "pqc.meta.nacsa_phase"
    family = ProbeFamily.PQC_META
    framework_tags = ("nacsa-9:phase-tracking", "bukukerja:phase-tracking")

    async def applies(self, ctx: ScanContext) -> bool:
        return True

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        today = date.today()
        fasa, label, deadline, days = _current_fasa(today)

        if days < 0:
            sev = Severity.HIGH
            cls = Classification.SANGAT_TINGGI
            note = f"PAST DEADLINE for {fasa} {label} (overdue by {-days} days)"
        elif days < 30:
            sev = Severity.HIGH
            cls = Classification.TINGGI
            note = f"{fasa} {label} deadline in {days} days — escalation window"
        elif days < 90:
            sev = Severity.MED
            cls = Classification.SEDERHANA
            note = f"{fasa} {label} deadline in {days} days — plan migration tasks"
        else:
            sev = Severity.INFO
            cls = Classification.INFO
            note = f"{fasa} {label} deadline in {days} days"

        emit(Finding(
            probe_id=self.id,
            algorithm="NACSA-Fasa",
            classification=cls,
            severity=sev,
            title=f"NACSA Arahan #9 — current {fasa} {label}",
            evidence={
                "today": today.isoformat(),
                "current_fasa": fasa,
                "fasa_label": label,
                "deadline": deadline.isoformat(),
                "days_remaining": days,
                "note": note,
                "timeline": [
                    {"fasa": "Fasa 1", "label": "Persediaan (Assess)",   "deadline": "2025-12-31"},
                    {"fasa": "Fasa 2", "label": "Pemilihan (Select)",    "deadline": "2026-06-30"},
                    {"fasa": "Fasa 3", "label": "Pengesahan (Validate)", "deadline": "2026-12-31"},
                    {"fasa": "Fasa 4", "label": "Pelaksanaan (Deploy)",  "deadline": "2027-06-30"},
                    {"fasa": "Fasa 5", "label": "Pemantauan (Monitor)",  "deadline": "ongoing from 2027-07-01"},
                ],
            },
        ))
