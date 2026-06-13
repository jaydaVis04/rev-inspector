from __future__ import annotations

from pathlib import Path


def scan_yara(path: Path, rules_path: Path | None = None) -> list[str]:
    try:
        import yara
    except ImportError:
        return []

    if rules_path is None:
        rules_path = Path(__file__).resolve().parent.parent / "rules" / "suspicious_strings.yar"
    if not rules_path.exists():
        return []

    rules = yara.compile(filepath=str(rules_path))
    return sorted(match.rule for match in rules.match(str(path)))
