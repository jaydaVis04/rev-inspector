from __future__ import annotations

import zipfile
from pathlib import Path


SCRIPT_SUFFIXES = {
    ".bat": "script",
    ".cmd": "script",
    ".js": "script",
    ".ps1": "script",
    ".py": "script",
    ".sh": "script",
    ".vbs": "script",
}

ARCHIVE_SUFFIXES = {
    ".7z": "archive",
    ".bz2": "archive",
    ".gz": "archive",
    ".rar": "archive",
    ".tar": "archive",
    ".xz": "archive",
    ".zip": "archive",
}


def detect_file_type(path: Path) -> str:
    head = path.read_bytes()[:4096]
    suffix = path.suffix.lower()

    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xca\xfe\xba\xbf",
    }:
        return "Mach-O"
    if zipfile.is_zipfile(path):
        if suffix == ".apk":
            return "APK"
        return "archive"
    if suffix == ".apk":
        return "APK"
    if suffix in SCRIPT_SUFFIXES or head.startswith(b"#!"):
        return "script"
    if suffix in ARCHIVE_SUFFIXES:
        return "archive"
    return "unknown"
