from __future__ import annotations

import re
from pathlib import Path


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile((rb"(?:[\x20-\x7e]\x00){4,}"))

CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "urls": re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE),
    "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "windows_paths": re.compile(r"\b[A-Za-z]:\\[^\s'\"<>|]+"),
    "unix_paths": re.compile(r"(?<!\w)/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+"),
    "registry_keys": re.compile(
        r"\b(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\[^\s'\"<>]+",
        re.IGNORECASE,
    ),
    "commands": re.compile(
        r"\b(?:cmd\.exe|powershell(?:\.exe)?|curl|wget|bash|sh|python|rundll32|regsvr32|schtasks)\b",
        re.IGNORECASE,
    ),
    "suspicious_apis": re.compile(
        r"\b(?:CreateProcess[AW]?|WinExec|ShellExecute[AW]?|InternetOpen(?:Url)?[AW]?|"
        r"URLDownloadToFile[AW]?|VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|"
        r"OpenProcess|LoadLibrary[AW]?|GetProcAddress|RegSetValue(?:Ex)?[AW]?)\b",
        re.IGNORECASE,
    ),
}


def extract_strings(path: Path, min_length: int = 4) -> list[str]:
    data = path.read_bytes()
    values: set[str] = set()

    for match in ASCII_RE.finditer(data):
        if len(match.group()) >= min_length:
            values.add(match.group().decode("utf-8", errors="replace"))

    for match in UTF16LE_RE.finditer(data):
        decoded = match.group().decode("utf-16le", errors="replace")
        if len(decoded) >= min_length:
            values.add(decoded)

    return sorted(values)


def categorize_strings(values: list[str]) -> dict[str, list[str]]:
    categorized: dict[str, list[str]] = {category: [] for category in CATEGORY_PATTERNS}
    categorized["other"] = []

    for value in values:
        matched = False
        for category, pattern in CATEGORY_PATTERNS.items():
            hits = sorted(set(pattern.findall(value)))
            if hits:
                categorized[category].extend(hits)
                matched = True
        if not matched:
            categorized["other"].append(value)

    return {category: sorted(set(items))[:200] for category, items in categorized.items() if items}
