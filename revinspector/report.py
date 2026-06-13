from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .entropy import file_entropy
from .filetype import detect_file_type
from .hashes import file_hashes
from .imports import parse_imports_exports
from .indicators import build_findings, risk_from_findings, summarize
from .metadata import collect_metadata
from .models import AnalysisReport
from .strings import categorize_strings, extract_strings
from .yara_scan import scan_yara


def analyze_file(path: Path, yara_rules: Path | None = None) -> AnalysisReport:
    path = path.expanduser().resolve()
    file_type = detect_file_type(path)
    architecture, compiler_hints, sections = collect_metadata(path, file_type)
    imports, exports = parse_imports_exports(path, file_type)
    strings = categorize_strings(extract_strings(path))
    yara_matches = scan_yara(path, yara_rules)
    entropy_value = file_entropy(path)
    findings = build_findings(imports, strings, sections, entropy_value, yara_matches)

    report = AnalysisReport(
        path=path,
        file_type=file_type,
        size=path.stat().st_size,
        hashes=file_hashes(path),
        architecture=architecture,
        compiler_hints=compiler_hints,
        sections=sections,
        imports=imports,
        exports=exports,
        strings=strings,
        yara_matches=yara_matches,
        findings=findings,
    )
    report.risk = risk_from_findings(findings)
    report.summary = summarize(findings)
    return report


def to_json(report: AnalysisReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def to_text(report: AnalysisReport) -> str:
    data = report.to_dict()
    lines = [
        f"File: {data['file']}",
        f"Type: {data['type']}",
        f"Size: {data['size']} bytes",
        f"SHA256: {data['hashes']['sha256']}",
        f"Architecture: {data['architecture'] or 'unknown'}",
        f"Risk: {data['risk'].title()}",
        f"Summary: {data['summary']}",
        "",
    ]
    _append_list(lines, "Compiler hints", data["compiler_hints"])
    _append_sections(lines, data["sections"])
    _append_list(lines, "Imports", data["imports"])
    _append_list(lines, "Exports", data["exports"])
    _append_strings(lines, data["strings"])
    _append_list(lines, "YARA matches", data["yara_matches"])
    _append_findings(lines, data["findings"])
    return "\n".join(lines).rstrip() + "\n"


def _append_list(lines: list[str], title: str, values: list[str], limit: int = 40) -> None:
    if not values:
        return
    lines.append(f"{title}:")
    for value in values[:limit]:
        lines.append(f"  - {value}")
    if len(values) > limit:
        lines.append(f"  - ... {len(values) - limit} more")
    lines.append("")


def _append_sections(lines: list[str], sections: list[dict[str, Any]]) -> None:
    if not sections:
        return
    lines.append("Sections:")
    for section in sections:
        flags = ",".join(section["flags"]) if section["flags"] else "-"
        lines.append(f"  - {section['name']} size={section['size']} entropy={section['entropy']} flags={flags}")
    lines.append("")


def _append_strings(lines: list[str], strings: dict[str, list[str]]) -> None:
    if not strings:
        return
    lines.append("Strings:")
    for category, values in strings.items():
        if category == "other":
            continue
        lines.append(f"  {category}:")
        for value in values[:20]:
            lines.append(f"    - {value}")
        if len(values) > 20:
            lines.append(f"    - ... {len(values) - 20} more")
    lines.append("")


def _append_findings(lines: list[str], findings: list[dict[str, str]]) -> None:
    if not findings:
        return
    lines.append("Indicators:")
    for finding in findings:
        lines.append(f"  - [{finding['severity']}] {finding['category']}: {finding['value']}")
        if finding["description"]:
            lines.append(f"    {finding['description']}")
    lines.append("")
