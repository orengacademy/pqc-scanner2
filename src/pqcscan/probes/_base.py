from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from pqcscan.core.types import Capability, Finding, ProbeFamily


@dataclass(slots=True)
class OTTarget:
    host: str
    port: int
    proto_hint: str | None = None  # "modbus" | "s7" | "opcua" | "dnp3" | ...


@dataclass(slots=True)
class ScanContext:
    scan_id: int
    mode: str  # "root" | "user"
    available_capabilities: set[Capability]
    scan_paths: list[Path] = field(default_factory=list)
    server_target: str | None = None
    ot_targets: list[OTTarget] = field(default_factory=list)


Emitter = Callable[[Finding], None]


class Probe(ABC):
    """Base class for all probes. Subclasses set class-level metadata."""

    id: str = ""
    family: ProbeFamily = ProbeFamily.AUX
    requires: frozenset[Capability] = frozenset()
    framework_tags: tuple[str, ...] = ()
    enabled_default: bool = True
    version: str = "0.1.0"

    async def applies(self, ctx: ScanContext) -> bool:
        """Quick gate. Default: yes if all required caps are available."""
        return self.requires.issubset(ctx.available_capabilities)

    @abstractmethod
    async def run(self, ctx: ScanContext, emit: Emitter) -> None:
        """Do the work; call emit(Finding(...)) for each result."""
        raise NotImplementedError
