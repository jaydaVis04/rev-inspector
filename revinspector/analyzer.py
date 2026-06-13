from __future__ import annotations

from pathlib import Path
from typing import Any

from .entropy import file_entropy
from .report import analyze_file as analyze_report


def analyze_file(path: Path) -> dict[str, Any]:
    """Compatibility facade for GUI code that expects a dictionary report."""
    report = analyze_report(path)
    data = report.to_dict()
    data["file_type"] = data["type"]
    data["size_bytes"] = data["size"]
    data["sha256"] = data["hashes"]["sha256"]
    data["entropy"] = round(file_entropy(path), 3)
    data["string_count"] = sum(len(values) for values in data["strings"].values())
    data["sample_strings"] = _sample_strings(data)
    data["indicators"] = [finding["value"] for finding in data["findings"]]
    data["hex_preview"] = _hex_preview(path)
    return data


def _hex_preview(path: Path, length: int = 256, width: int = 16) -> list[dict[str, str]]:
    data = path.read_bytes()[:length]
    rows = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        rows.append(
            {
                "offset": f"{offset:08x}",
                "hex": hex_bytes,
                "ascii": ascii_text,
            }
        )
    return rows


def _sample_strings(data: dict[str, Any], limit: int = 50) -> list[str]:
    strings: list[str] = []
    for category, values in data["strings"].items():
        if category == "other":
            continue
        strings.extend(values)
    strings.extend(data["strings"].get("other", []))
    return strings[:limit]
