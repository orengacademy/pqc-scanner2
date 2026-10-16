"""Formula-injection guard for XLSX exports.

openpyxl types any string starting with "=" as a formula, so a hostile cert
subject / package name / file path like ``=cmd|' /C calc'!A0`` would execute
in the auditor's spreadsheet. Force every string cell back to the string type.
"""
from __future__ import annotations

from collections.abc import Iterable


def force_text(cells: Iterable) -> None:
    for c in cells:
        if isinstance(c.value, str) and c.data_type == "f":
            c.data_type = "s"
