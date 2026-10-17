"""Render docs/BAKEOFF.md from a bakeoff.json result: a pure function of the result plus FOLLOW_UPS and notes()."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

import normalise as nm

SAMPLES = "crypto-samples/"

# One line per kind of miss: (tool family, surface, canonical algorithm | "*") -> "<verdict>: what to do".
# Verdicts: fix (a pqcscan gap to close), alias (a naming difference), scope (the tools look at different things).
_XMSS = ("**fix:** XMSS and LMS are NIST SP 800-208 stateful hash-based signatures, i.e. PQC. Add them to "
         "code.crypto_primitives so they classify as pqc-ready.")
_HYBRID = ("**alias:** these name the hybrid idiom itself; pqcscan lists the component algorithms (ML-KEM, ML-DSA, "
           "X25519) found in the same file.")
_CHACHA = "**alias:** pqcscan reports ChaCha20 alone; the Poly1305 half is the same primitive."
FOLLOW_UPS: dict[tuple[str, str, str], str] = {
    # anvil offers one group at a time and lists every group the server accepts
    ("anvil", "tls", "*"): (
        "**fix:** net.tls.kex_groups reports only the group the server prefers. Enumerate every accepted group (one "
        "ClientHello per group) so a hybrid server that still accepts classical-only groups shows as a downgrade "
        "path."),
    # QuantaSeek with checks off
    ("quantaseek", "tls", "tls1.2"): (
        "**scope:** pqcscan records the negotiated TLS 1.2 version only in the cipher-suite finding. Informational; "
        "no change planned."),
    ("quantaseek", "tls", "rsasha256"): (
        "**scope:** pqcscan keeps the certificate signature hash in evidence (`signature_hash`) and flags the RSA key. "
        "No change planned."),
    # cryptoscan
    ("cryptoscan", "cert", "x509certificate"): (
        "**scope:** cryptoscan matches the PEM header and says a file is a certificate. pqcscan parses it and reports "
        "the key algorithm. No change."),
    ("cryptoscan", "code", "ec"): (
        "**fix:** code.ts.go does not detect `ecdsa.GenerateKey(elliptic.P256(), ...)`. Add ECDSA / elliptic-curve "
        "keygen to the Go rules and a `go-ec-real` corpus case."),
    ("cryptoscan", "code", "xmss"): _XMSS,
    ("cryptoscan", "code", "lms"): _XMSS,
    ("cryptoscan", "code", "sha512"): (
        "**fix, low priority:** pqcscan lists SHA-256 but not SHA-384 or SHA-512. They are quantum-safe, so only CBOM "
        "completeness is at stake."),
    ("cryptoscan", "code", "hybridkem"): _HYBRID,
    ("cryptoscan", "code", "compositesignature"): _HYBRID,
    ("cryptoscan", "code", "poly1305"): _CHACHA,
    ("cryptoscan", "code", "tls"): (
        "**scope:** a TLS option block is configuration, not an algorithm. pqcscan covers TLS settings through the "
        "net.tls.* and fs.conf.* probes."),
    ("cryptoscan", "code", "*"): (
        "**scope:** key-derivation and MAC inventory. Quantum-safe and outside the PQC-risk question; add only for "
        "CBOM completeness."),
}

ORDER = ["anvil", "quantaseek", "quantaseek-noverify", "cryptoscan"]
SHORT = {"anvil": "anvil", "quantaseek": "QuantaSeek", "quantaseek-noverify": "QuantaSeek (checks off)",
         "cryptoscan": "cryptoscan"}
TECHNIQUE = {
    "pqcscan": "in-process probes: TLS handshakes, X.509 and PKCS#12 parsing, tree-sitter and regex source scan",
    "anvil": "advertised key-exchange groups only, no full handshake; TLS and SSH",
    "quantaseek": ("rustls handshake, parses ServerHello; verifies the chain against public roots. Built with one "
                   "`[lib]` edit to `Cargo.toml` because the pinned commit does not compile"),
    "quantaseek-noverify": ("patched rebuild ([patch](../benchmark/bakeoff/quantaseek-noverify.patch)): certificate "
                            "and signature checks accepted, plus the same `[lib]` edit"),
    "cryptoscan": "regex over source and config files; does not parse certificate contents",
}

Pred = Callable[[str], bool]


def _family(tool: str) -> str:
    return tool.split("-")[0]


def _counts(diff: dict[str, list[list[str]]], surface: str, keep: Pred = lambda t: True) -> tuple[int, int, int]:
    def n(bucket: str) -> int:
        return sum(1 for t, s, _ in diff[bucket] if s == surface and keep(t))
    return n("pqcscan_only"), n("tool_only"), n("both")


def _follow_up(tool: str, surface: str, canon: str) -> str:
    fam = _family(tool)
    return (FOLLOW_UPS.get((fam, surface, canon)) or FOLLOW_UPS.get((fam, surface, "*"))
            or "unreviewed: triage before the next release.")


def _misses(result: dict[str, Any], tool: str) -> list[tuple[str, str, list[str], list[str]]]:
    """Everything only the tool reports, grouped by (surface, follow-up): (surface, follow-up, names, targets)."""
    by_key: dict[tuple[str, str], set[str]] = defaultdict(set)
    for target, surface, canon in result["summary"][tool]["diff"]["tool_only"]:
        by_key[(surface, canon)].add(target)
    spelling: dict[tuple[str, str], str] = {}
    for row in result["rows"][tool]:
        spelling.setdefault((row["surface"], nm.canonical(row["algorithm"])), row["algorithm"])
    groups: dict[tuple[str, str], tuple[list[str], set[str]]] = {}
    for (surface, canon), targets in sorted(by_key.items()):
        names, where = groups.setdefault((surface, _follow_up(tool, surface, canon)), ([], set()))
        names.append(spelling.get((surface, canon), canon))
        where |= targets
    return [(s, text, names, sorted(where)) for (s, text), (names, where) in groups.items()]


def _where(targets: list[str]) -> str:
    short = [t.removeprefix("endpoint-") for t in targets]
    return ", ".join(short[:3]) + (f" and {len(short) - 3} more" if len(short) > 3 else "")


def render(result: dict[str, Any]) -> str:
    tools = [t for t in ORDER if t in result["summary"]]
    sha, d = result["commit"][:7], result["date"]
    n_cert, n_code = len(result["targets"]["cert"]), len(result["targets"]["code"])
    runner = result.get("runner_commit")
    out = [f"**Run:** measured commit `{sha}` (pqcscan {result['tools']['pqcscan'].get('version')})"
           + (f", runner `{runner}`" if runner else "")
           + f" · `{result['command']}` · {d[:4]}-{d[4:6]}-{d[6:]} · {result['box']}", "",
           "# Bake-off: pqcscan against competing FOSS scanners", "",
           "Every tool scans the same targets from the accuracy corpus. Raw output is kept in "
           f"`benchmark/bakeoff/results/{d}/raw/`. `benchmark/bakeoff/normalise.py` maps each tool's output to one "
           "row schema and the diff compares `(target, surface, algorithm)` with algorithm names folded to a family "
           "(`X25519MLKEM768` = `x25519_kyber768`, `RSA-2048` = `RSA`). Method and limits: "
           "[`benchmark/bakeoff/README.md`](../benchmark/bakeoff/README.md).", "",
           "The corpus was written for pqcscan, so it favours pqcscan on file and certificate targets. One extra "
           "source set, cryptoscan's own sample files, is added to give the competitor home ground.", "",
           "## Tools", "", "| Tool | Commit | Version | Surfaces | Technique |", "|---|---|---|---|---|"]
    for name in ["pqcscan", *ORDER]:
        spec = result["tools"].get(name)
        if spec is None:
            continue
        commit = f"[`{spec['commit'][:10]}`]({spec['repo']}/commit/{spec['commit']})" if spec["commit"] else "this repo"
        out.append(f"| {spec['title']} | {commit} | {spec.get('version') or '-'} | {', '.join(spec['surfaces'])} "
                   f"| {TECHNIQUE.get(name, '')} |")

    out += ["", "## Per-target diff", "",
            "Distinct `(target, surface, algorithm)` keys. *pqcscan-only* and *tool-only* are keys one side reports "
            "and the other does not; *both* is the overlap. Each tool is compared on the surfaces it claims. anvil "
            "lists accepted key-exchange groups and nothing else, so it is also shown against pqcscan's group rows "
            "alone (scoped), which is the fair comparison; the raw counts include every pqcscan finding anvil does "
            "not try to make.", "",
            "| Target | Tool | pqcscan-only | tool-only | both |", "|---|---|---:|---:|---:|"]

    def in_samples(t: str) -> bool:
        return t.startswith(SAMPLES)

    def not_samples(t: str) -> bool:
        return not t.startswith(SAMPLES)

    for tool in tools:
        diff = result["summary"][tool]["diff"]
        for surface in result["summary"][tool]["surfaces"]:
            if surface == "tls":
                rows = [(t, lambda x, t=t: x == t) for t in result["targets"]["tls"]]
            elif surface == "cert":
                rows = [(f"certificate files ({n_cert} fixtures)", lambda x: True)]
            else:
                rows = [(f"source tree, corpus cases ({n_code} fixtures)", not_samples),
                        ("source tree, cryptoscan's own samples (6 files)", in_samples)]
            out += [f"| {label} | {SHORT[tool]} | " + " | ".join(map(str, _counts(diff, surface, keep))) + " |"
                    for label, keep in rows]

    for tool in tools:
        scoped = result["summary"][tool].get("scoped")
        if scoped:
            out += ["", f"{SHORT[tool]}, scoped to {scoped['label']} (pqcscan side: net.tls.kex_groups and "
                        "net.tls.pqc_handshake rows):", "",
                    "| Target | pqcscan-only | tool-only | both |", "|---|---:|---:|---:|"]
            out += [f"| {t} | " + " | ".join(map(str, _counts(scoped["diff"], "tls", lambda x, t=t: x == t))) + " |"
                    for t in result["targets"]["tls"]]

    out += ["", "Totals per tool and surface (raw counts, and scoped where a tool has a scope):", "",
            "| Tool | Surface | Comparison | pqcscan-only | tool-only | both |", "|---|---|---|---:|---:|---:|"]
    for tool in tools:
        summary = result["summary"][tool]
        for s in summary["surfaces"]:
            out.append(f"| {SHORT[tool]} | {s} | raw | " + " | ".join(map(str, _counts(summary["diff"], s))) + " |")
            if summary.get("scoped") and s == "tls":
                out.append(f"| {SHORT[tool]} | {s} | scoped: {summary['scoped']['label']} | "
                           + " | ".join(map(str, _counts(summary["scoped"]["diff"], s))) + " |")
    for tool in tools:
        if result["tools"][tool].get("note"):
            out += ["", f"{SHORT[tool]} {result['tools'][tool]['note']}."]

    out += ["", "## What each tool finds that pqcscan misses", ""]
    for tool in tools:
        out += [f"### {result['tools'][tool]['title']}", ""]
        misses = _misses(result, tool)
        if not result["rows"][tool]:
            out += ["It reported nothing on any target, so there is nothing to miss. See below.", ""]
        elif not misses:
            out += ["Nothing. Every key it reports on the shared targets, pqcscan reports too.", ""]
        out += [f"- **{', '.join(names)}** ({surface}; {len(t)} target{'s' * (len(t) != 1)}: {_where(t)}). {text}"
                for surface, text, names, t in misses]
        out.append("")

    out += notes(result)
    return "\n".join(out).rstrip() + "\n"


def notes(result: dict[str, Any]) -> list[str]:
    neg, meta = result["negative_fixture_hits"], result["meta"]
    pq, cs, ts = neg.get("pqcscan"), neg.get("cryptoscan"), neg.get("pqcscan code.ts.* only")
    out = ["## What else the run showed", ""]
    if pq and cs and ts:
        out.append(
            "- **pqcscan-only is not all credit.** "
            f"On the {pq['of']} fixtures whose weak token sits only in a comment or string literal, "
            f"pqcscan's code.crypto_primitives flags {pq['fixtures']}, cryptoscan flags {cs['fixtures']}, "
            f"and the AST probes (code.ts.*) flag {ts['fixtures']}. "
            "**fix:** run the source stripper in code.crypto_primitives as the AST probes do.")
    out += [
        "- **QuantaSeek, stock, completed no handshake.** It checks the chain against bundled public roots and the "
        "server name, has no flag to relax either (`--ignore-mismatch` is parsed and ignored), and the fixtures are "
        "private-CA and carry no subjectAltName. The checks-off row is a patched rebuild that accepts them.",
        "- **QuantaSeek dials port 443 only.** The target's port is ignored and its port loop is not used for the real "
        "handshake, so the run bridges each fixture to 127.0.0.1:443 inside a private network namespace. The pinned "
        "commit also fails to compile until the library crate is named `quanta_seek`.",
        "- **Silence is not a verdict.** QuantaSeek (checks off) fails on the TLS 1.0, RSA-key-exchange, NULL-cipher "
        "and mTLS servers. anvil returns an empty result with no error on every server that is not TLS 1.3, and on "
        "the ML-DSA-65 hybrid server. Neither says it could not look.",
        "- **cryptoscan on certificates reads text, not keys.** DER and PKCS#12 hits come from names inside the file "
        "(`ecdsa`, `ed25519` in the subject), so the cert-tree overlap is partly coincidence.",
    ]
    cc = meta.get("cli_crosscheck")
    if cc:
        same = all(v["identical"] for v in cc.values())
        verdict = "identical on all three" if same else "DIFFERENT, see bakeoff.json"
        out.append("- **In-process pqcscan equals the CLI.** The runner uses the probes `--target` and `--path` bind, "
                   "because the CLI has no probe filter and adds a multi-minute host sweep. One real `pqcscan scan` "
                   f"per surface (tls, cert, code) was compared with the in-process keys: {verdict}.")
    return out
