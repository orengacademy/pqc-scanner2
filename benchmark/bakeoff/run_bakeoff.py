#!/usr/bin/env python
"""Bake-off: pqcscan against competing FOSS scanners on shared targets, with a finding-level diff.

Targets (all from the committed accuracy corpus, ``benchmark/corpus/cases``):
  tls   eight local TLS servers started by ``run_benchmark.tls_endpoint`` (the same helper for every tool)
  cert  one directory holding the certificate / PKCS#12 fixtures
  code  one source tree holding the Java / Kotlin / Go / JS / Python / C# / Rust / PHP fixtures

Tools: pqcscan (in-process, the same probes ``--target`` / ``--path`` bind), anvilsecure/pqcscan, QuantaSeek and
csnp/cryptoscan (each a pinned-commit docker image built from ``Dockerfile.<tool>``).

    PYTHONPATH=src .venv/bin/python benchmark/bakeoff/run_bakeoff.py [--build] [--tools a,b] [--date YYYYMMDD]

Raw tool output goes to ``results/<date>/raw/``, normalised rows and diffs to ``results/<date>/bakeoff.json`` and
the write-up to ``docs/BAKEOFF.md``.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(HERE.parent)]
import normalise as nm  # noqa: E402
import run_benchmark as rb  # noqa: E402

from pqcscan.core.types import Capability  # noqa: E402
from pqcscan.probes._base import ScanContext  # noqa: E402
from pqcscan.probes._registry import default_registry  # noqa: E402
from pqcscan.runner.runner import bind_context  # noqa: E402

CASES = HERE.parent / "corpus" / "cases"
MANIFEST = HERE.parent / "corpus" / "manifest.yaml"

# Fixed target lists: the bake-off must not change when the corpus grows. These are the cases committed at 10f789c.
ENDPOINTS = ["endpoint-tls10-only", "endpoint-rsa-kex-only", "endpoint-null-cipher", "endpoint-tls12-ecdhe",
             "endpoint-mtls-tls12", "endpoint-tls13-x25519", "endpoint-tls13-hybrid-ed25519",
             "endpoint-tls13-hybrid-mldsa65"]
CERT_CASES = ["cert-ecdsa-p256-pem", "cert-ecdsa-p384-der", "cert-ed25519-der", "cert-ed25519-pem", "cert-mldsa65",
              "cert-mldsa65-der", "cert-rsa1024", "cert-rsa2048-der", "cert-rsa2048-pem", "cert-rsa3072-pem",
              "cert-rsa4096-der", "p12-ecdsa-p256-test", "p12-ed25519-nopass", "p12-rsa2048-changeit",
              "p12-truststore-mldsa65", "p12-truststore-rsa2048"]
CODE_CASES = ["cs-clean-sha256", "cs-comment-md5", "cs-des-real", "cs-md5-real", "cs-rsa-real", "cs-string-md5",
              "cs-verbatim-md5", "go-clean-sha256", "go-comment-md5", "go-md5-real", "go-string-md5",
              "java-comment-md5", "java-des-real", "java-md5-real", "java-string-md5", "js-clean-sha256",
              "js-comment-md5", "js-md5-real", "js-string-md5", "kt-clean-sha256", "kt-comment-md5", "kt-md5-real",
              "kt-raw-string-md5", "kt-rsa-real", "kt-string-md5", "php-comment-md5", "php-md5-real",
              "php-string-md5", "py-clean-sha256", "py-comment-md5", "py-des-real", "py-ec-real", "py-md5-real",
              "py-rsa2048", "py-sha1-alias", "py-string-md5", "rust-clean-sha256", "rust-comment-md5",
              "rust-des-real", "rust-md5-real", "rust-raw-string-md5", "rust-rsa-real", "rust-string-md5"]
SAMPLES_DIR = "crypto-samples"  # csnp/cryptoscan's own samples, inside the code tree: the competitor's home ground
# Fixtures where the weak token sits only in a comment or a string literal: any finding there is a false positive.
NOT_REAL = re.compile(r"(comment|string|verbatim)")

# The pqcscan probes that `--target host:port` (tls) and `--path dir` (cert, code) point at the fixtures.
PQC_TLS = ["net.tls.versions", "net.tls.kex_groups", "net.tls.cert_chain", "net.tls.cert_chain_tls13",
           "net.tls.pqc_handshake", "net.tls.https"]
PQC_CERT = ["fs.cert.x509", "fs.cert.pqc_x509", "fs.keystore.pkcs12", "fs.keystore.jks"]
PQC_CODE_PREFIX = "code."

TOOLS: dict[str, dict[str, Any]] = {
    "pqcscan": {"title": "pqcscan (this repo)", "surfaces": ["tls", "cert", "code"], "repo": None},
    "anvil": {"title": "anvilsecure/pqcscan", "surfaces": ["tls"], "repo": "https://github.com/anvilsecure/pqcscan",
              "image": "bakeoff-anvil", "lang": "Rust"},
    "quantaseek": {"title": "Mehrn0ush/QuantaSeek", "surfaces": ["tls"], "dockerfile": "quantaseek", "target": "stock",
                   "repo": "https://github.com/Mehrn0ush/QuantaSeek", "image": "bakeoff-quantaseek", "lang": "Rust"},
    "quantaseek-noverify": {"title": "QuantaSeek, cert checks off", "surfaces": ["tls"], "dockerfile": "quantaseek",
                            "target": "noverify", "repo": "https://github.com/Mehrn0ush/QuantaSeek",
                            "image": "bakeoff-quantaseek-noverify", "lang": "Rust"},
    "cryptoscan": {"title": "csnp/cryptoscan", "surfaces": ["cert", "code"], "repo": "https://github.com/csnp/cryptoscan",
                   "image": "bakeoff-cryptoscan", "lang": "Go"},
}
RELAY_IMAGE = "bakeoff-relay"


# --------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------

def sh(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def pinned_commit(tool: str) -> str:
    """The commit a tool image is built from: the single source of truth is ``ARG COMMIT`` in its Dockerfile."""
    text = (HERE / f"Dockerfile.{TOOLS[tool].get('dockerfile', tool)}").read_text(encoding="utf-8")
    return re.search(r"ARG COMMIT=([0-9a-f]{40})", text).group(1)  # type: ignore[union-attr]


def ensure_images(tools: list[str], build: bool) -> None:
    for tool in tools:
        image = TOOLS[tool].get("image")
        if image and sh(["docker", "image", "inspect", image]).returncode != 0:
            if not build:
                raise SystemExit(f"image {image} missing: run with --build (or `docker build -f Dockerfile.{tool}`)")
            spec = TOOLS[tool]
            target = ["--target", spec["target"]] if "target" in spec else []
            subprocess.run(["docker", "build", "-f", str(HERE / f"Dockerfile.{spec.get('dockerfile', tool)}"), *target,
                            "-t", image, str(HERE)], check=True)
    needs_relay = any(t.startswith("quantaseek") for t in tools)
    if needs_relay and sh(["docker", "image", "inspect", RELAY_IMAGE]).returncode != 0:
        subprocess.run(["docker", "build", "-f", str(HERE / "Dockerfile.relay"), "-t", RELAY_IMAGE, str(HERE)],
                       check=True)


def stage(dest: Path, names: list[str]) -> Path:
    """Copy fixture directories side by side so every tool scans byte-identical files."""
    dest.mkdir(parents=True)
    for name in names:
        shutil.copytree(CASES / name, dest / name)
    return dest


def extract_samples(dest: Path) -> None:
    """Copy cryptoscan's own sample files out of its image (they ship in the pinned commit)."""
    name = f"bakeoff-samples-{os.getpid()}"
    subprocess.run(["docker", "create", "--name", name, TOOLS["cryptoscan"]["image"]], check=True, capture_output=True)
    try:
        subprocess.run(["docker", "cp", f"{name}:/samples", str(dest)], check=True, capture_output=True)
    finally:
        sh(["docker", "rm", "-f", name])


def dump(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------------------------------
# pqcscan (in-process: the probes `--target` / `--path` bind, via the runner's own bind_context)
# --------------------------------------------------------------------------------------------------

def _finding_dict(f: Any, root: Path | None) -> dict[str, Any]:
    ev = dict(f.evidence)
    title = f.title
    if root is not None:  # keep raw files free of the temp staging path
        for key in ("path", "file"):
            if isinstance(ev.get(key), str):
                ev[key] = os.path.relpath(ev[key], root) if ev[key].startswith(str(root)) else ev[key]
        title = title.replace(str(root), "<root>")
    return {"probe_id": f.probe_id, "algorithm": f.algorithm, "classification": f.classification.value,
            "severity": f.severity.name, "title": title, "evidence": ev}


def pqcscan_run(probe_ids: list[str], ctx: ScanContext, root: Path | None = None) -> list[dict[str, Any]]:
    registry = default_registry()
    out: list[dict[str, Any]] = []
    for pid in probe_ids:
        probe = bind_context(registry.get(pid), ctx)
        found: list[Any] = []
        try:
            asyncio.run(asyncio.wait_for(probe.run(ctx, found.append), timeout=90))
        except Exception as exc:  # a probe that dies is a data point, not a reason to stop the bake-off
            out.append({"probe_id": pid, "algorithm": "N/A", "classification": "info", "severity": "INFO",
                        "title": f"probe error: {exc!r}", "evidence": {}})
        out.extend(_finding_dict(f, root) for f in found)
    return out


def pqcscan_tls(port: int) -> list[dict[str, Any]]:
    ctx = ScanContext(scan_id=0, mode="root", available_capabilities=set(Capability),
                      server_target=f"127.0.0.1:{port}")
    return pqcscan_run(PQC_TLS, ctx)


def pqcscan_tree(root: Path, probe_ids: list[str]) -> list[dict[str, Any]]:
    ctx = ScanContext(scan_id=0, mode="root", available_capabilities=set(Capability), scan_paths=[root])
    return pqcscan_run(probe_ids, ctx, root)


def code_probe_ids() -> list[str]:
    return [p for p in default_registry().ids() if p.startswith(PQC_CODE_PREFIX)]


def pqcscan_cli(args: list[str], probe_ids: set[str]) -> list[dict[str, Any]]:
    """Run the real CLI (`python -m pqcscan scan ...`) and read its findings back from the SQLite DB it wrote."""
    with tempfile.TemporaryDirectory(prefix="bakeoff-cli-") as tmp:
        db = Path(tmp) / "scan.db"
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        done = sh([sys.executable, "-m", "pqcscan", "scan", "--json", "--fail-on", "none", "--db", str(db), *args],
                  env=env, cwd=ROOT)
        if done.returncode != 0:
            raise RuntimeError(f"pqcscan CLI failed ({done.returncode}): {done.stderr[-400:]}")
        con = sqlite3.connect(db)
        rows = con.execute("select probe_id, algorithm, classification, severity, title, evidence from findings"
                           ).fetchall()
        con.close()
    return [{"probe_id": p, "algorithm": a, "classification": c, "severity": s, "title": t, "evidence": json.loads(e)}
            for p, a, c, s, t, e in rows if p in probe_ids]


# --------------------------------------------------------------------------------------------------
# competitors (docker)
# --------------------------------------------------------------------------------------------------

def docker_run(image: str, args: list[str], *, network: str = "host", mounts: list[str] | None = None,
               timeout: int = 180) -> subprocess.CompletedProcess[str]:
    cmd = ["docker", "run", "--rm", "--network", network, "--user", f"{os.getuid()}:{os.getgid()}"]
    for m in mounts or []:
        cmd += ["-v", m]
    return sh([*cmd, image, *args], timeout=timeout)


def run_anvil(port: int, out: Path) -> dict[str, Any]:
    # --test-nonpqc-algos makes it probe classical groups too; without it a classical server reports nothing at all
    done = docker_run("bakeoff-anvil", ["tls-scan", "--test-nonpqc-algos", "-t", f"127.0.0.1:{port}", "-o",
                                        "/out/anvil.json"], mounts=[f"{out}:/out"])
    if done.returncode != 0:
        return {"error": done.stderr[-400:]}
    return json.loads((out / "anvil.json").read_text(encoding="utf-8"))


class UnixRelay:
    """Bridge a unix socket to one 127.0.0.1 TCP port, so a container in a private network namespace can reach a
    host loopback server. Needed because QuantaSeek ignores the port in its target and dials <target>:443 (its
    own port loop is cosmetic), and 443 is taken on this host: it would scan the wrong server."""

    def __init__(self, sock: Path, port: int) -> None:
        self.sock, self.port = sock, port
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    async def _pipe(self, src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        with contextlib.suppress(OSError):
            while data := await src.read(65536):
                dst.write(data)
                await dst.drain()
        dst.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            up_r, up_w = await asyncio.open_connection("127.0.0.1", self.port)
        except OSError:
            writer.close()
            return
        await asyncio.gather(self._pipe(reader, up_w), self._pipe(up_r, writer))

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        server = self.loop.run_until_complete(asyncio.start_unix_server(self._handle, path=str(self.sock)))
        self.sock.chmod(0o666)
        self.ready.set()
        self.loop.run_forever()
        server.close()

    def __enter__(self) -> UnixRelay:
        self.thread.start()
        self.ready.wait(5)
        return self

    def __exit__(self, *exc: object) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


def run_quantaseek(port: int, image: str) -> dict[str, Any]:
    name = f"bakeoff-relay-{os.getpid()}"
    with tempfile.TemporaryDirectory(prefix="bakeoff-sock-") as tmp, UnixRelay(Path(tmp) / "r.sock", port):
        started = sh(["docker", "run", "-d", "--rm", "--name", name, "-v", f"{tmp}:/s", RELAY_IMAGE,
                      "TCP-LISTEN:443,bind=127.0.0.1,fork,reuseaddr", "UNIX-CONNECT:/s/r.sock"])
        if started.returncode != 0:
            return {"error": started.stderr[-400:]}
        try:
            for _ in range(50):  # wait for the listener inside the namespace
                if sh(["docker", "exec", name, "nc", "-z", "127.0.0.1", "443"]).returncode == 0:
                    break
                time.sleep(0.1)
            done = sh(["docker", "run", "--rm", "--network", f"container:{name}", image, "-q",
                       "--tls12", "--ignore-mismatch", "127.0.0.1"], timeout=180)
        finally:
            sh(["docker", "rm", "-f", name])
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return {"error": (done.stdout + done.stderr)[-400:]}


def run_cryptoscan(tree: Path) -> dict[str, Any]:
    done = docker_run("bakeoff-cryptoscan", ["scan", "/t", "--format", "json", "--include-quantum-safe"],
                      mounts=[f"{tree}:/t:ro"])
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return {"error": (done.stdout + done.stderr)[-400:]}


# --------------------------------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------------------------------

@contextlib.contextmanager
def endpoints() -> Iterator[dict[str, int]]:
    ports: dict[str, int] = {}
    with contextlib.ExitStack() as stack:
        for name in ENDPOINTS:
            try:
                ports[name] = stack.enter_context(rb.tls_endpoint(CASES / name / "endpoint.yaml"))
            except rb.UnservableFixtureError as exc:
                print(f"SKIP {name}: {exc}", file=sys.stderr)
        yield ports


def collect(tools: list[str], raw_dir: Path, work: Path, cli_check: bool) -> dict[str, Any]:
    """Run every tool on every target and save its raw output; return run metadata (rows are built from the raw)."""
    certs, tree = stage(work / "certs", CERT_CASES), stage(work / "src", CODE_CASES)
    if "cryptoscan" in tools:
        extract_samples(tree / SAMPLES_DIR)  # same tree, so pqcscan and cryptoscan scan identical bytes
    import pqcscan
    meta: dict[str, Any] = {"cli_crosscheck": None, "versions": {"pqcscan": pqcscan.__version__}}
    code_probes = code_probe_ids()

    def keep(tool: str, name: str, raw: Any) -> None:
        dump(raw_dir / f"{tool}-{name}.json", raw)

    with endpoints() as ports:
        meta["ports_skipped"] = [n for n in ENDPOINTS if n not in ports]
        for name, port in ports.items():
            if "pqcscan" in tools:
                keep("pqcscan", name, pqcscan_tls(port))
            if "anvil" in tools:
                keep("anvil", name, run_anvil(port, raw_dir))
                (raw_dir / "anvil.json").unlink(missing_ok=True)
            for tool in (t for t in tools if t.startswith("quantaseek")):
                keep(tool, name, run_quantaseek(port, TOOLS[tool]["image"]))
        if cli_check and "pqcscan" in tools and ports:
            ep = "endpoint-tls13-hybrid-ed25519"  # the richest fixture: hybrid group, Ed25519 key, TLS 1.3
            probe_ep = ep if ep in ports else next(iter(ports))
            meta["cli_crosscheck"] = cli_crosscheck(ports[probe_ep], probe_ep, certs, tree, code_probes)
    if "pqcscan" in tools:
        keep("pqcscan", "certs", pqcscan_tree(certs, PQC_CERT))
        keep("pqcscan", "code", pqcscan_tree(tree, code_probes))
    if "cryptoscan" in tools:
        keep("cryptoscan", "certs", run_cryptoscan(certs))
        keep("cryptoscan", "code", run_cryptoscan(tree))
    for tool in tools:
        if tool.startswith("quantaseek"):
            meta["versions"][tool] = sh(["docker", "run", "--rm", TOOLS[tool]["image"], "-V"]
                                                        ).stdout.split()[-1]
    return meta


def normalise_all(tools: list[str], raw_dir: Path) -> tuple[dict[str, list[nm.Row]], dict[str, Any]]:
    """Rebuild every tool's rows from the saved raw files; also return versions and tool errors found in them."""
    rows: dict[str, list[nm.Row]] = {t: [] for t in tools}
    info: dict[str, Any] = {"versions": {}, "errors": []}

    def load(tool: str, name: str) -> Any:
        raw = json.loads((raw_dir / f"{tool}-{name}.json").read_text(encoding="utf-8"))
        if isinstance(raw, dict) and raw.get("error"):
            info["errors"].append(f"{tool}/{name}: {str(raw['error'])[:200]}")
        return raw

    for tool in tools:
        for name in ENDPOINTS:
            if not (raw_dir / f"{tool}-{name}.json").exists():
                continue
            raw = load(tool, name)
            rows[tool] += nm.NORMALISERS[tool](raw, name) if tool != "cryptoscan" else []
            if tool == "anvil":
                info["versions"]["anvil"] = raw.get("version")
        for name, surface in (("certs", "cert"), ("code", "code")):
            if not (raw_dir / f"{tool}-{name}.json").exists():
                continue
            raw = load(tool, name)
            if tool == "pqcscan":
                rows[tool] += nm.normalise_pqcscan(raw)
            elif tool == "cryptoscan":
                rows[tool] += nm.normalise_cryptoscan(raw, surface)
                info["versions"]["cryptoscan"] = (raw.get("tool") or {}).get("version")
    return rows, info


def cli_crosscheck(port: int, name: str, certs: Path, tree: Path, code_probes: list[str]) -> dict[str, Any]:
    """Show the in-process probe run equals the real CLI for the same target (the CLI has no probe filter and adds
    a multi-minute host sweep, so the bake-off itself uses the in-process path)."""
    jobs = {"tls": ([f"--target=127.0.0.1:{port}"], PQC_TLS, pqcscan_tls(port), name),
            "cert": ([f"--path={certs}"], PQC_CERT, pqcscan_tree(certs, PQC_CERT), None),
            "code": ([f"--path={tree}"], code_probes, pqcscan_tree(tree, code_probes), None)}
    results: dict[str, Any] = {}

    def one(kind: str) -> None:
        args, probes, inproc, target = jobs[kind]
        cli = pqcscan_cli(args, set(probes))
        if kind != "tls":  # the CLI keeps absolute staging paths; make them relative like the in-process raw
            for f in cli:
                for key in ("path", "file"):
                    v = f["evidence"].get(key)
                    if isinstance(v, str) and v.startswith(str(certs if kind == "cert" else tree)):
                        f["evidence"][key] = os.path.relpath(v, certs if kind == "cert" else tree)
        a = {nm.key_of(r) for r in nm.normalise_pqcscan(cli, target)}
        b = {nm.key_of(r) for r in nm.normalise_pqcscan(inproc, target)}
        results[kind] = {"cli_keys": len(a), "inproc_keys": len(b), "identical": a == b,
                         "cli_only": sorted(a - b)[:10], "inproc_only": sorted(b - a)[:10]}

    threads = [threading.Thread(target=one, args=(k,)) for k in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def negative_hits(rows: list[nm.Row], only_probe_prefix: str = "") -> dict[str, int]:
    """Weak-algorithm findings on fixtures where the token sits only in a comment or string: any hit is a false
    positive. Returns finding keys, distinct fixtures hit, and the number of such fixtures."""
    hits = [r for r in rows if r["surface"] == "code" and r["pq_safe"] is False
            and NOT_REAL.search(r["target"].split("/")[0]) and r["detail"].startswith(only_probe_prefix)]
    return {"findings": len({(r["target"], nm.canonical(r["algorithm"])) for r in hits}),
            "fixtures": len({r["target"].split("/")[0] for r in hits}),
            "of": sum(1 for c in CODE_CASES if NOT_REAL.search(c))}


def summarise(rows: dict[str, list[nm.Row]]) -> dict[str, Any]:
    """Per tool, per target: pqcscan-only / tool-only / both on (target, surface, canonical algorithm)."""
    base = rows.get("pqcscan", [])
    out: dict[str, Any] = {}
    for tool, tool_rows in rows.items():
        if tool == "pqcscan":
            continue
        surfaces = set(TOOLS[tool]["surfaces"])
        mine = [r for r in tool_rows if r["surface"] in surfaces]
        theirs = [r for r in base if r["surface"] in surfaces]
        d = nm.diff_sets(theirs, mine)
        by_target: dict[str, dict[str, int]] = {}
        for bucket, keys in d.items():
            for target, _surface, _alg in keys:
                by_target.setdefault(target, {"pqcscan_only": 0, "tool_only": 0, "both": 0})[bucket] += 1
        out[tool] = {"surfaces": sorted(surfaces), "totals": {k: len(v) for k, v in d.items()}, "by_target": by_target,
                     "diff": {k: [list(x) for x in v] for k, v in d.items()}}
    return out


def environment() -> str:
    docker = sh(["docker", "version", "--format", "{{.Server.Version}}"]).stdout.strip()
    cpu = next((ln.split(":", 1)[1].strip() for ln in Path("/proc/cpuinfo").read_text().splitlines()
                if ln.startswith("model name")), platform.processor())
    return f"{platform.system()} {platform.release()}, {cpu} x{os.cpu_count()}, docker {docker}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tools", default="pqcscan,anvil,quantaseek,quantaseek-noverify,cryptoscan")
    ap.add_argument("--date", default=dt.date.today().strftime("%Y%m%d"))
    ap.add_argument("--build", action="store_true", help="build missing docker images")
    ap.add_argument("--no-cli-crosscheck", action="store_true", help="skip the slow real-CLI comparison")
    ap.add_argument("--no-doc", action="store_true", help="write results only, not docs/BAKEOFF.md")
    ap.add_argument("--from-raw", action="store_true",
                    help="skip scanning: rebuild rows, diffs and the doc from results/<date>/raw (after editing "
                         "normalise.py or report.py)")
    args = ap.parse_args(argv)
    out_dir = HERE / "results" / args.date
    raw_dir = out_dir / "raw"
    old = json.loads((out_dir / "bakeoff.json").read_text(encoding="utf-8")) if args.from_raw else {}
    tools = list(old["tools"]) if args.from_raw else args.tools.split(",")
    if args.from_raw:
        meta = old["meta"]
    else:
        ensure_images([t for t in tools if t != "pqcscan"], args.build)
        raw_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="bakeoff-") as tmp:
            meta = collect(tools, raw_dir, Path(tmp), not args.no_cli_crosscheck)
    rows, info = normalise_all(tools, raw_dir)
    meta = {**meta, **info, "versions": {**meta.get("versions", {}), **info["versions"]}}
    result = {
        "date": args.date, "box": old.get("box") or environment(),
        "commit": old.get("commit") or sh(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip(),
        "command": old.get("command") or "PYTHONPATH=src .venv/bin/python benchmark/bakeoff/run_bakeoff.py "
                                         + " ".join(argv if argv is not None else sys.argv[1:]),
        "tools": {t: {**{k: v for k, v in TOOLS[t].items() if k != "image"},
                      "commit": pinned_commit(t) if t != "pqcscan" else None,
                      "version": meta["versions"].get(t)} for t in tools},
        "targets": {"tls": ENDPOINTS, "cert": CERT_CASES, "code": CODE_CASES, "code_extra": [SAMPLES_DIR]},
        "rows": rows, "summary": summarise(rows), "meta": meta,
        "negative_fixture_hits": {**{t: negative_hits(r) for t, r in rows.items()},
                                  "pqcscan code.ts.* only": negative_hits(rows.get("pqcscan", []), "code.ts.")},
    }
    dump(out_dir / "bakeoff.json", result)
    print(json.dumps({t: s["totals"] for t, s in result["summary"].items()}, indent=1))
    if not args.no_doc:
        import report  # local module, imported late so tests of the normalisers do not need it
        (ROOT / "docs" / "BAKEOFF.md").write_text(report.render(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
