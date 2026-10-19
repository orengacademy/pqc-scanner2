#!/usr/bin/env python3
"""Reconcile a pqcscan fleet against the customer's asset inventory.

    pqcscan export --scan fleet --format cbom -o fleet.cbom.json
    curl -s -H "Authorization: Bearer $TOKEN" $COLLECTOR/api/fleet > fleet.json
    python benchmark/fleet/reconcile.py --cbom fleet.cbom.json --fleet fleet.json \
        --inventory inventory.csv --out-dir out/

Inputs (at least one of --cbom / --fleet):
  --cbom       CycloneDX CBOM from `pqcscan export --scan fleet --format cbom`. Gives reporting hosts
               (pqcscan:host / pqcscan:machine_id properties) and TLS versions.
  --fleet      `GET /api/fleet` JSON (a list, or {"hosts": [...]}). Gives last_seen and revoked.
               `pqcscan fleet summary --json` also loads, but carries no machine_id / last_seen / revoked.
  --inventory  CSV: hostname,machine_id,owner,environment,expected_tls_min,expected_cert_cn
               (only hostname is required; machine_id is optional per row).

Outputs discrepancies.csv and discrepancies.md in --out-dir.
Exit code: 0 no discrepancies, 1 discrepancies found, 2 bad input.

Checks the input cannot support are listed under "Not assessed" in the report instead of passing silently.
Notably the CBOM exported today carries no certificate subject, so cert_cn_mismatch needs a
`pqcscan:cert_subject` / `pqcscan:cert_cn` property (or "CN=" in the component description).
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

STALE_AFTER = timedelta(hours=48)

CLASSES = ("missing_from_fleet", "unknown_to_inventory", "identity_mismatch", "weak_match",
           "stale", "revoked", "tls_below_expected", "cert_cn_mismatch")

ACTIONS = {
    "missing_from_fleet": "Install and enroll the agent, or remove the host from the inventory if decommissioned.",
    "unknown_to_inventory": "Add the host to the inventory, or find and remove the unauthorised agent.",
    "identity_mismatch": "Confirm which record is correct; fix the inventory or re-enroll the host (cloned image?).",
    "weak_match": "Confirm the FQDN and short name are the same host, then align the inventory hostname.",
    "stale": "Check the agent service and network path to the collector; re-run the agent.",
    "revoked": "Re-enroll the host with a fresh token, or confirm the revocation was intended.",
    "tls_below_expected": "Raise the minimum TLS version on the service, or lower the expectation with sign-off.",
    "cert_cn_mismatch": "Replace the certificate, or correct the expected CN in the inventory.",
}

_TLS_ORDER = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_TLS_RE = re.compile(r"(?<![A-Za-z])(SSLv?\s?[23]|TLSv?\s?1(?:\.[0-3])?)(?![\d.])", re.I)
_CN_RE = re.compile(r"(?:^|[,/\s])CN=([^,/]+)", re.I)


class InputError(Exception):
    """Bad input file or argument; main() maps it to exit code 2."""


def norm_tls(text: str) -> str | None:
    """'TLSv1.2' / 'TLS 1.2' / 'tls1.2' / '1.2' / 'SSLv3' -> canonical name, or None if not a version."""
    t = text.strip().lower().replace(" ", "")
    if re.fullmatch(r"1\.[0-3]", t):
        t = "tlsv" + t
    m = re.fullmatch(r"(ssl|tls)v?(\d(?:\.\d)?)", t)
    if not m:
        return None
    name = f"{'SSL' if m[1] == 'ssl' else 'TLS'}v{m[2]}"
    if name == "TLSv1":
        name = "TLSv1.0"
    return name if name in _TLS_ORDER else None


def _short(hostname: str) -> str:
    return hostname.split(".", 1)[0]


@dataclass
class Observed:
    hostname: str = ""
    machine_id: str = ""
    last_seen: datetime | None = None
    revoked: bool = False
    from_fleet: bool = False                       # last_seen is only known from the fleet JSON
    has_revoked: bool = False                      # the fleet JSON carried a 'revoked' field for this host
    last_seen_is_proxy: bool = False               # last_seen came from finished_at (fleet summary --json)
    tls: list[tuple[str, str]] = field(default_factory=list)   # (canonical version, component description)
    cert_cns: set[str] = field(default_factory=set)
    consumed: bool = False


@dataclass
class InvRow:
    hostname: str
    machine_id: str = ""
    owner: str = ""
    environment: str = ""
    expected_tls_min: str | None = None
    expected_cert_cn: str = ""


@dataclass
class Row:
    cls: str
    host: str
    detail: str


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise InputError(f"unparseable timestamp in fleet JSON: {value!r}") from None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read {path}: {e}") from None


def load_fleet(path: Path) -> list[Observed]:
    data = _load_json(path)
    hosts = data.get("hosts") if isinstance(data, dict) else data
    if not isinstance(hosts, list) or not all(isinstance(h, dict) for h in hosts):
        raise InputError(f"{path}: expected a list of hosts or an object with a 'hosts' list")
    out = []
    for h in hosts:
        if not (h.get("hostname") or h.get("machine_id")):
            raise InputError(f"{path}: host entry without hostname or machine_id: {h!r}")
        out.append(Observed(hostname=str(h.get("hostname") or ""), machine_id=str(h.get("machine_id") or ""),
                            last_seen=_parse_ts(h.get("last_seen") or h.get("finished_at")),
                            revoked=bool(h.get("revoked")), from_fleet=True, has_revoked="revoked" in h,
                            last_seen_is_proxy=not h.get("last_seen") and bool(h.get("finished_at"))))
    return out


def load_cbom(path: Path) -> list[Observed]:
    data = _load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("components"), list):
        raise InputError(f"{path}: not a CycloneDX document (no 'components' list)")
    by_key: dict[tuple[str, str], Observed] = {}
    for comp in data["components"]:
        props = {p.get("name"): p.get("value") for p in comp.get("properties", []) if isinstance(p, dict)}
        host, mid = str(props.get("pqcscan:host") or ""), str(props.get("pqcscan:machine_id") or "")
        if not (host or mid):
            continue                                # single-host CBOM component: no fleet attribution
        obs = by_key.setdefault((mid, host.lower()), Observed(hostname=host, machine_id=mid))
        desc = str(comp.get("description") or "")
        probe = str(props.get("pqcscan:probe") or "net.")
        m = _TLS_RE.search(desc) if probe.startswith("net.") else None
        if m and (ver := norm_tls(m[1])):
            obs.tls.append((ver, desc))
        subject = props.get("pqcscan:cert_cn") or props.get("pqcscan:cert_subject") or ""
        cn = _CN_RE.search(str(subject)) or _CN_RE.search(desc)
        if cn:
            obs.cert_cns.add(cn[1].strip().lower())
        elif subject and "=" not in str(subject):
            obs.cert_cns.add(str(subject).strip().lower())   # bare CN in pqcscan:cert_cn
    return list(by_key.values())


def merge_observed(*sources: list[Observed]) -> list[Observed]:
    """Union of sources; the same machine_id (else same lower-cased hostname) is one host."""
    merged: list[Observed] = []
    for obs in (o for src in sources for o in src):
        for m in merged:
            same_id = bool(obs.machine_id) and obs.machine_id == m.machine_id
            same_name = (not (obs.machine_id and m.machine_id) and bool(obs.hostname)
                         and obs.hostname.lower() == m.hostname.lower())
            if same_id or same_name:
                m.hostname = m.hostname or obs.hostname
                m.machine_id = m.machine_id or obs.machine_id
                if m.last_seen is None and obs.from_fleet:
                    m.last_seen_is_proxy = obs.last_seen_is_proxy
                m.last_seen = m.last_seen or obs.last_seen
                m.revoked = m.revoked or obs.revoked
                m.has_revoked = m.has_revoked or obs.has_revoked
                m.from_fleet = m.from_fleet or obs.from_fleet
                m.tls += obs.tls
                m.cert_cns |= obs.cert_cns
                break
        else:
            merged.append(obs)
    return merged


def load_inventory(path: Path) -> list[InvRow]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise InputError(f"cannot read {path}: {e}") from None
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames or "hostname" not in [f.strip() for f in reader.fieldnames]:
        raise InputError(f"{path}: missing required 'hostname' column")
    rows = []
    for n, raw in enumerate(reader, start=2):
        r = {(k or "").strip(): (v or "").strip() for k, v in raw.items()}
        if not r.get("hostname"):
            raise InputError(f"{path}:{n}: empty hostname")
        exp = None
        if r.get("expected_tls_min"):
            exp = norm_tls(r["expected_tls_min"])
            if exp is None:
                raise InputError(f"{path}:{n}: unrecognised expected_tls_min {r['expected_tls_min']!r} "
                                 f"(use e.g. TLSv1.2)")
        rows.append(InvRow(r["hostname"], r.get("machine_id", ""), r.get("owner", ""), r.get("environment", ""),
                           exp, r.get("expected_cert_cn", "")))
    if not rows:
        raise InputError(f"{path}: inventory has no rows")
    return rows


def _assign(inventory: list[InvRow], observed: list[Observed]) -> list[tuple[Observed | None, str]]:
    """Match each inventory row to a reporting host; how is id | name | weak | ''.

    Passes run over the whole inventory, strongest first, so the result does not depend on row order:
    machine_id, then exact case-insensitive hostname, then the short-name heuristic.
    """
    out: list[tuple[Observed | None, str]] = [(None, "")] * len(inventory)

    def take(i: int, o: Observed, how: str) -> None:
        o.consumed = True
        out[i] = (o, how)

    for i, inv in enumerate(inventory):
        if inv.machine_id:
            o = next((o for o in observed if not o.consumed and o.machine_id == inv.machine_id), None)
            if o:
                take(i, o, "id")
    for i, inv in enumerate(inventory):
        if out[i][0] is None:
            o = next((o for o in observed if not o.consumed and o.hostname.lower() == inv.hostname.lower()), None)
            if o:
                take(i, o, "name")
    for i, inv in enumerate(inventory):
        if out[i][0] is None:
            # ponytail: short-name heuristic only; a real CMDB alias table is the upgrade if this over-matches
            o = next((o for o in observed if not o.consumed and o.hostname
                      and _short(o.hostname).lower() == _short(inv.hostname).lower()
                      and ("." not in o.hostname or "." not in inv.hostname)), None)
            if o:
                take(i, o, "weak")
    return out


def reconcile(inventory: list[InvRow], observed: list[Observed], now: datetime) -> tuple[list[Row], list[str]]:
    rows: list[Row] = []
    for o in observed:
        o.consumed = False
    unassessed: Counter[str] = Counter()
    for inv, (o, how) in zip(inventory, _assign(inventory, observed), strict=True):
        if o is None:
            rows.append(Row("missing_from_fleet", inv.hostname,
                            f"in inventory (owner={inv.owner or '-'}, env={inv.environment or '-'}) "
                            f"but no host with that name or machine_id has reported"))
            continue
        name = o.hostname or inv.hostname
        if how == "weak":
            rows.append(Row("weak_match", inv.hostname,
                            f"inventory '{inv.hostname}' matched reporting host '{o.hostname}' by short name only"))
        elif how == "id" and _short(o.hostname).lower() != _short(inv.hostname).lower():
            rows.append(Row("identity_mismatch", inv.hostname,
                            f"machine_id {inv.machine_id} is reporting as '{o.hostname}', "
                            f"inventory says '{inv.hostname}'"))
        elif how == "id" and o.hostname.lower() != inv.hostname.lower():
            rows.append(Row("weak_match", inv.hostname,
                            f"machine_id matches but hostname differs: inventory '{inv.hostname}', "
                            f"reporting '{o.hostname}'"))
        elif how == "name" and inv.machine_id and o.machine_id and inv.machine_id != o.machine_id:
            rows.append(Row("identity_mismatch", inv.hostname,
                            f"hostname matches but machine_id differs: inventory {inv.machine_id}, "
                            f"reporting {o.machine_id}"))
        if o.revoked:
            rows.append(Row("revoked", name, "agent token is revoked; the host cannot submit scans"))
        elif not o.has_revoked:
            unassessed["revoked"] += 1
        if o.from_fleet:
            if o.last_seen_is_proxy:
                unassessed["last_seen proxy"] += 1
            if o.last_seen is None:
                rows.append(Row("stale", name, "enrolled but has never reported a scan"))
            elif now - o.last_seen > STALE_AFTER:
                hours = int((now - o.last_seen).total_seconds() // 3600)
                rows.append(Row("stale", name, f"last seen {o.last_seen.isoformat()} ({hours} h ago, limit 48 h)"))
        else:
            unassessed["stale"] += 1
        if inv.expected_tls_min and not o.tls:
            unassessed["tls_below_expected"] += 1
        elif inv.expected_tls_min:
            floor = _TLS_ORDER.index(inv.expected_tls_min)
            for ver in sorted({v for v, _ in o.tls if _TLS_ORDER.index(v) < floor}):
                desc = next(d for v, d in o.tls if v == ver)
                rows.append(Row("tls_below_expected", name,
                                f"observed {ver}, expected at least {inv.expected_tls_min}: {desc}"))
        if inv.expected_cert_cn:
            if not o.cert_cns:
                unassessed["cert_cn_mismatch"] += 1
            elif inv.expected_cert_cn.lower() not in o.cert_cns:
                rows.append(Row("cert_cn_mismatch", name,
                                f"expected CN {inv.expected_cert_cn}, observed {', '.join(sorted(o.cert_cns))}"))
    rows += [Row("unknown_to_inventory", o.hostname or o.machine_id,
                 f"reporting (machine_id={o.machine_id or '-'}) but not in the inventory")
             for o in observed if not o.consumed]
    notes = []
    if unassessed["stale"]:
        notes.append(f"stale: {unassessed['stale']} matched host(s) came only from the CBOM, "
                     f"which has no last_seen. Pass --fleet to assess them.")
    if unassessed["revoked"]:
        notes.append(f"revoked: {unassessed['revoked']} matched host(s) have no 'revoked' field in the input "
                     f"(CBOM only, or `pqcscan fleet summary --json`), so revocation was not checked. "
                     f"Pass the output of GET /api/fleet as --fleet.")
    if unassessed["last_seen proxy"]:
        notes.append(f"stale: {unassessed['last_seen proxy']} host(s) have no last_seen, so the finish time of their "
                     f"latest scan (finished_at) was used as a proxy. It can differ from the last agent contact.")
    if unassessed["tls_below_expected"]:
        notes.append(f"tls_below_expected: {unassessed['tls_below_expected']} host(s) have an expected_tls_min but "
                     f"the input holds no TLS observation for them, so the TLS version was not checked.")
    if unassessed["cert_cn_mismatch"]:
        notes.append(f"cert_cn_mismatch: {unassessed['cert_cn_mismatch']} host(s) have an expected_cert_cn but "
                     f"the input carries no certificate subject for them, so the CN was not checked.")
    return sorted(rows, key=lambda r: (CLASSES.index(r.cls), r.host.lower())), notes


def _csv_cell(s: str) -> str:
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s    # spreadsheet formula injection


def _md_cell(s: str) -> str:
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def write_outputs(rows: list[Row], notes: list[str], out_dir: Path, meta: dict[str, str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "discrepancies.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["class", "host", "detail", "suggested_action"])
        for r in rows:
            w.writerow([r.cls, _csv_cell(r.host), _csv_cell(r.detail), ACTIONS[r.cls]])
    counts = Counter(r.cls for r in rows)
    md = ["# Fleet reconciliation: discrepancies", "",
          *[f"- {k}: {v}" for k, v in meta.items()], "",
          f"## Summary: {len(rows)} discrepanc{'y' if len(rows) == 1 else 'ies'}", "",
          "| Class | Count |", "|---|---:|", *[f"| {c} | {counts[c]} |" for c in CLASSES], ""]
    if notes:
        md += ["## Not assessed", "", *[f"- {n}" for n in notes], ""]
    md += ["## Discrepancies", ""]
    if rows:
        md += ["| Class | Host | Detail | Suggested action |", "|---|---|---|---|",
               *[f"| {r.cls} | {_md_cell(r.host)} | {_md_cell(r.detail)} | {ACTIONS[r.cls]} |" for r in rows]]
    else:
        md.append("None.")
    (out_dir / "discrepancies.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    ap = argparse.ArgumentParser(description="Reconcile a pqcscan fleet against an asset inventory.")
    ap.add_argument("--cbom", type=Path, help="fleet CBOM JSON (pqcscan export --scan fleet --format cbom)")
    ap.add_argument("--fleet", type=Path, help="fleet JSON (GET /api/fleet or pqcscan fleet summary --json)")
    ap.add_argument("--inventory", type=Path, required=True, help="inventory CSV")
    ap.add_argument("--out-dir", type=Path, default=Path("."), help="where to write discrepancies.csv/.md")
    args = ap.parse_args(argv)
    if not (args.cbom or args.fleet):
        ap.error("give --cbom and/or --fleet")
    now = now or datetime.now(UTC)
    try:
        inventory = load_inventory(args.inventory)
        observed = merge_observed(load_fleet(args.fleet) if args.fleet else [],
                                  load_cbom(args.cbom) if args.cbom else [])
        rows, notes = reconcile(inventory, observed, now)
        write_outputs(rows, notes, args.out_dir, {
            "Run": now.isoformat(timespec="seconds"), "Inventory": f"{args.inventory} ({len(inventory)} hosts)",
            "Reporting hosts": str(len(observed)), "CBOM": str(args.cbom or "-"), "Fleet JSON": str(args.fleet or "-")})
    except (InputError, OSError) as e:
        print(f"reconcile: {e}", file=sys.stderr)
        return 2
    print(f"{len(rows)} discrepancies, {len(notes)} check(s) not assessed -> {args.out_dir / 'discrepancies.md'}")
    return 1 if rows else 0


if __name__ == "__main__":
    sys.exit(main())
