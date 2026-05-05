"""sbom.os.windows — installed-products list via Windows registry."""
from __future__ import annotations

import contextlib
import sys

from pqcscan.core.types import ProbeFamily
from pqcscan.probes._base import Emitter, Probe, ScanContext
from pqcscan.probes._sbom_helper import emit_package

_REG_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)


class SbomOsWindows(Probe):
    id = "sbom.os.windows"
    family = ProbeFamily.SBOM
    framework_tags = ("bukukerja:sbom", "mykripto:sbom")

    async def applies(self, ctx: ScanContext) -> bool:
        return sys.platform == "win32"

    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        if sys.platform != "win32":
            return
        try:
            import winreg
        except ImportError:
            return
        for hive_root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for key_path in _REG_KEYS:
                try:
                    base = winreg.OpenKey(hive_root, key_path)
                except OSError:
                    continue
                try:
                    i = 0
                    while True:
                        try:
                            sub_name = winreg.EnumKey(base, i)
                        except OSError:
                            break
                        try:
                            sub = winreg.OpenKey(base, sub_name)
                        except OSError:
                            i += 1
                            continue
                        name = ""
                        version = ""
                        with contextlib.suppress(OSError):
                            name = winreg.QueryValueEx(sub, "DisplayName")[0]
                        with contextlib.suppress(OSError):
                            version = winreg.QueryValueEx(sub, "DisplayVersion")[0]
                        winreg.CloseKey(sub)
                        if name:
                            emit_package(self.id, emit,
                                         name=name, version=version,
                                         manager="winreg", purl_type="generic/windows")
                        i += 1
                finally:
                    winreg.CloseKey(base)
