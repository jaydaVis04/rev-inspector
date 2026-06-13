from __future__ import annotations

from pathlib import Path


def disassemble_preview(path: Path, architecture: str | None, max_bytes: int = 128) -> list[str]:
    try:
        import capstone
    except ImportError:
        return []

    mode = _capstone_mode(architecture)
    if mode is None:
        return []

    engine = capstone.Cs(*mode)
    data = path.read_bytes()[:max_bytes]
    return [f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".strip() for insn in engine.disasm(data, 0)]


def _capstone_mode(architecture: str | None) -> tuple[int, int] | None:
    if not architecture:
        return None
    name = architecture.lower()
    try:
        import capstone
    except ImportError:
        return None
    if name in {"x86", "i386"}:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32
    if name in {"x86_64", "amd64"}:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64
    if "arm64" in name or "aarch64" in name:
        return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
    if "arm" in name:
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
    return None
