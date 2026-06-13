from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Finding:
    category: str
    value: str
    severity: str = "info"
    description: str = ""


@dataclass(slots=True)
class SectionInfo:
    name: str
    size: int
    entropy: float
    virtual_address: str | None = None
    flags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisReport:
    path: Path
    file_type: str
    size: int
    hashes: dict[str, str]
    architecture: str | None = None
    compiler_hints: list[str] = field(default_factory=list)
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    strings: dict[str, list[str]] = field(default_factory=dict)
    yara_matches: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    risk: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": str(self.path),
            "type": self.file_type,
            "size": self.size,
            "hashes": self.hashes,
            "architecture": self.architecture,
            "compiler_hints": self.compiler_hints,
            "sections": [asdict(section) for section in self.sections],
            "imports": self.imports,
            "exports": self.exports,
            "strings": self.strings,
            "yara_matches": self.yara_matches,
            "findings": [asdict(finding) for finding in self.findings],
            "summary": self.summary,
            "risk": self.risk,
        }
