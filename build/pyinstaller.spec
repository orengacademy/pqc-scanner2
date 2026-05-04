# PyInstaller spec — produces a single-file pqcscan binary.
#
# Build:    pyinstaller build/pyinstaller.spec
# Output:   dist/pqcscan  (Linux/macOS) or dist/pqcscan.exe (Windows)
#
# This spec is consumed by PyInstaller as a Python script. Do not import
# it; do not run it directly. Analysis, PYZ, EXE, COLLECT, BUNDLE are
# injected by PyInstaller into its globals at exec time.

import sys
from pathlib import Path

_REPO_ROOT = Path.cwd()
_SRC = _REPO_ROOT / "src"

# Bundle every data file pqcscan reads at runtime.
DATAS = [
    (str(_SRC / "pqcscan" / "ui" / "templates"), "pqcscan/ui/templates"),
    (str(_SRC / "pqcscan" / "ui" / "static"),    "pqcscan/ui/static"),
    (str(_SRC / "pqcscan" / "renderers" / "templates"),
     "pqcscan/renderers/templates"),
    (str(_SRC / "pqcscan" / "compliance" / "frameworks"),
     "pqcscan/compliance/frameworks"),
    (str(_SRC / "pqcscan" / "probes" / "_semgrep_rules"),
     "pqcscan/probes/_semgrep_rules"),
]

# Optional offline pack: scripts/fetch-offline-tools.sh stages syft +
# grype binaries under ./tools. If present at build time, bundle them
# so pqcscan.util.offline_pack.resolve_tool() finds them at runtime
# under sys._MEIPASS / 'tools'. Skip silently if absent — the binary
# still works, probes just fall back to system PATH.
_TOOLS_DIR = _REPO_ROOT / "tools"
if _TOOLS_DIR.is_dir() and any(_TOOLS_DIR.iterdir()):
    DATAS.append((str(_TOOLS_DIR), "tools"))

# Probe modules are imported dynamically by default_registry(), so
# PyInstaller can't see them via static analysis. Glob the source tree
# so this stays in sync as new probes land.
_PROBES_DIR = _SRC / "pqcscan" / "probes"
HIDDEN_IMPORTS = [
    "pqcscan.probes._registry",
    "pqcscan.probes._base",
    "pqcscan.compliance.engine",
    "pqcscan.runner.runner",
    "pqcscan.runner.event_bus",
    "pqcscan.runner.capabilities",
    "pqcscan.renderers.pdf_technical",
    "pqcscan.renderers.pdf_executive",
    "pqcscan.renderers.xlsx_bukukerja",
    "pqcscan.renderers.xlsx_generic",
    "weasyprint",
    "openpyxl",
    "cyclonedx_python_lib",
    "multipart",  # python-multipart, used by FastAPI Form()
]
for path in sorted(_PROBES_DIR.glob("*.py")):
    name = path.stem
    if name.startswith("_"):
        continue
    HIDDEN_IMPORTS.append(f"pqcscan.probes.{name}")


a = Analysis(
    [str(_SRC / "pqcscan" / "cli" / "main.py")],
    pathex=[str(_SRC)],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="pqcscan" + (".exe" if sys.platform == "win32" else ""),
    debug=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
