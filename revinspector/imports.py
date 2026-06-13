from __future__ import annotations

from pathlib import Path


def parse_imports_exports(path: Path, file_type: str) -> tuple[list[str], list[str]]:
    if file_type == "PE":
        return _pe_imports_exports(path)
    return [], []


def _pe_imports_exports(path: Path) -> tuple[list[str], list[str]]:
    try:
        import pefile
    except ImportError:
        return [], []

    pe = pefile.PE(str(path), fast_load=False)
    imports: list[str] = []
    exports: list[str] = []

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode(errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
        for imported in entry.imports:
            if imported.name:
                name = imported.name.decode(errors="replace")
            else:
                name = f"ordinal_{imported.ordinal}"
            imports.append(f"{dll}!{name}")

    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir:
        for symbol in export_dir.symbols:
            if symbol.name:
                exports.append(symbol.name.decode(errors="replace"))
            else:
                exports.append(f"ordinal_{symbol.ordinal}")

    return sorted(set(imports)), sorted(set(exports))
