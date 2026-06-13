from __future__ import annotations

import json
from html import escape
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


def to_html(report: AnalysisReport) -> str:
    data = report.to_dict()
    title = f"Rev Inspector Report - {Path(data['file']).name}"
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="utf-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1">',
            f"  <title>{escape(title)}</title>",
            f"  <style>{_html_css()}</style>",
            "</head>",
            "<body>",
            "  <main>",
            f"    <h1>{escape(Path(data['file']).name)}</h1>",
            '    <p class="scope">Static analysis only. The submitted file was not executed.</p>',
            _summary_html(data),
            _findings_html(data["findings"]),
            _metadata_html(data),
            _sections_html(data["sections"]),
            _list_html("Imports", data["imports"]),
            _list_html("Exports", data["exports"]),
            _strings_html(data["strings"]),
            _list_html("YARA Matches", data["yara_matches"]),
            "  </main>",
            "</body>",
            "</html>",
        ]
    )


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


def _summary_html(data: dict[str, Any]) -> str:
    hashes = data["hashes"]
    return "\n".join(
        [
            '    <section class="summary-grid">',
            f"      <div><span>Risk</span><strong class=\"risk risk-{escape(data['risk'])}\">{escape(data['risk'].title())}</strong></div>",
            f"      <div><span>Type</span><strong>{escape(data['type'])}</strong></div>",
            f"      <div><span>Architecture</span><strong>{escape(data['architecture'] or 'unknown')}</strong></div>",
            f"      <div><span>Size</span><strong>{data['size']} bytes</strong></div>",
            f"      <div class=\"wide\"><span>SHA256</span><code>{escape(hashes['sha256'])}</code></div>",
            f"      <div class=\"wide\"><span>Summary</span><p>{escape(data['summary'])}</p></div>",
            "    </section>",
        ]
    )


def _metadata_html(data: dict[str, Any]) -> str:
    rows = [
        ("File", data["file"]),
        ("MD5", data["hashes"]["md5"]),
        ("SHA1", data["hashes"]["sha1"]),
        ("SHA256", data["hashes"]["sha256"]),
    ]
    if data["compiler_hints"]:
        rows.append(("Compiler hints", ", ".join(data["compiler_hints"])))
    return _table_html("Metadata", rows)


def _table_html(title: str, rows: list[tuple[str, str]]) -> str:
    body = "\n".join(
        f"        <tr><th>{escape(label)}</th><td>{escape(str(value))}</td></tr>"
        for label, value in rows
    )
    return "\n".join(
        [
            f"    <section><h2>{escape(title)}</h2>",
            "      <table>",
            body,
            "      </table>",
            "    </section>",
        ]
    )


def _findings_html(findings: list[dict[str, str]]) -> str:
    if not findings:
        return '    <section><h2>Indicators</h2><p class="empty">No indicators found.</p></section>'
    chunks = []
    for finding in findings:
        chunks.extend(
            [
                "        <li>",
                f"          <span class=\"badge {escape(finding['severity'])}\">{escape(finding['severity'])}</span>",
                f"          <strong>{escape(finding['value'])}</strong>",
                f"          <span>{escape(finding['category'])}</span>",
                f"          <p>{escape(finding['description'])}</p>",
                "        </li>",
            ]
        )
    items = "\n".join(chunks)
    return "\n".join(["    <section><h2>Indicators</h2>", "      <ul class=\"findings\">", items, "      </ul>", "    </section>"])


def _sections_html(sections: list[dict[str, Any]]) -> str:
    if not sections:
        return ""
    rows = "\n".join(
        "        <tr>"
        f"<td>{escape(section['name'])}</td>"
        f"<td>{section['size']}</td>"
        f"<td>{section['entropy']}</td>"
        f"<td>{escape(', '.join(section['flags']) or '-')}</td>"
        f"<td>{escape(section['virtual_address'] or '-')}</td>"
        "</tr>"
        for section in sections
    )
    return "\n".join(
        [
            "    <section><h2>Sections</h2>",
            "      <table>",
            "        <tr><th>Name</th><th>Size</th><th>Entropy</th><th>Flags</th><th>Virtual address</th></tr>",
            rows,
            "      </table>",
            "    </section>",
        ]
    )


def _list_html(title: str, values: list[str], limit: int = 80) -> str:
    if not values:
        return ""
    items = "\n".join(f"        <li><code>{escape(value)}</code></li>" for value in values[:limit])
    more = f"        <li class=\"muted\">... {len(values) - limit} more</li>" if len(values) > limit else ""
    return "\n".join([f"    <section><h2>{escape(title)}</h2>", "      <ul>", items, more, "      </ul>", "    </section>"])


def _strings_html(strings: dict[str, list[str]]) -> str:
    if not strings:
        return ""
    sections = ["    <section><h2>Strings</h2>"]
    for category, values in strings.items():
        if category == "other":
            continue
        sections.append(f"      <h3>{escape(category.replace('_', ' ').title())}</h3>")
        sections.append("      <ul>")
        for value in values[:60]:
            sections.append(f"        <li><code>{escape(value)}</code></li>")
        if len(values) > 60:
            sections.append(f"        <li class=\"muted\">... {len(values) - 60} more</li>")
        sections.append("      </ul>")
    sections.append("    </section>")
    return "\n".join(sections)


def _html_css() -> str:
    return """
body { margin: 0; background: #f6f7f9; color: #1f2937; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
main { max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; }
h1 { margin: 0; font-size: 28px; }
h2 { margin: 0 0 14px; font-size: 18px; }
h3 { margin: 18px 0 8px; font-size: 14px; color: #374151; }
section { margin-top: 18px; padding: 18px; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 9px 10px; border-top: 1px solid #e5e7eb; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { width: 180px; color: #4b5563; font-weight: 600; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
ul { margin: 0; padding-left: 20px; }
li { margin: 6px 0; }
.scope, .muted, .empty { color: #6b7280; }
.summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.summary-grid div { padding: 12px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fafafa; }
.summary-grid span { display: block; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.summary-grid strong { display: block; margin-top: 4px; font-size: 18px; }
.summary-grid .wide { grid-column: span 4; }
.summary-grid p { margin: 4px 0 0; }
.risk-low { color: #047857; }
.risk-medium { color: #b45309; }
.risk-high { color: #b91c1c; }
.findings { list-style: none; padding: 0; }
.findings li { padding: 12px 0; border-top: 1px solid #e5e7eb; }
.findings p { margin: 4px 0 0; color: #4b5563; }
.badge { display: inline-block; min-width: 54px; margin-right: 8px; padding: 2px 8px; border-radius: 999px; color: #fff; font-size: 12px; text-align: center; }
.badge.low { background: #059669; }
.badge.medium { background: #d97706; }
.badge.high { background: #dc2626; }
@media (max-width: 760px) { .summary-grid { grid-template-columns: 1fr; } .summary-grid .wide { grid-column: auto; } th { width: auto; } }
""".strip()


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
