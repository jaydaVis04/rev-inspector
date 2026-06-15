# Rev Inspector

Rev Inspector is a static binary inspection assistant for learning defensive reverse engineering and malware-analysis concepts without executing unknown samples!

It accepts a compiled file or script and produces a structured report with file type, hashes, extracted strings, metadata, entropy, imports, and suspicious indicators.

## Safety scope

- Static analysis only.
- Never executes unknown binaries.
- Intended for test binaries, open-source programs, CTF samples, and intentionally vulnerable training files.
- Does not include unpacking or bypassing protections for commercial software.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[analysis]"
rev-inspector path/to/sample
rev-inspector path/to/sample --html-out report.html
```

The core CLI works with only the Python standard library. Optional dependencies improve parsing:

- `pefile` for PE metadata and imports.
- `pyelftools` for ELF metadata.
- `macholib` for Mach-O metadata.
- `yara-python` for YARA rule matching.
- `capstone` for future disassembly features.

## Example

```bash
rev-inspector samples/example.sh --json
```

PE files get dependency-free header parsing for architecture, subsystem, entry point, image base, file characteristics, section flags, and section entropy. Installing `pefile` adds richer PE import/export parsing.

## Optional web UI

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn web.app:app --reload --port 8001
```

Open `http://127.0.0.1:8001` for the local workbench UI. Port 8000 is commonly used by other local tools, so 8001 is the documented default for this project. The UI uses a fixed topbar, left report rail, dense analysis tables, upload progress, current-session recent analyses, local analyst notes, and explicit static-analysis guardrails. The server stores uploads under `uploads/` for local review and never executes them.

```json
{
  "file": "samples/example.sh",
  "type": "script",
  "hashes": {
    "sha256": "..."
  },
  "summary": "This file appears to use networking and shell command indicators.",
  "risk": "medium"
}
```

## Project layout

```text
samples/
rules/
  suspicious_strings.yar
revinspector/
  filetype.py
  metadata.py
  strings.py
  imports.py
  entropy.py
  disasm.py
  indicators.py
  report.py
  cli.py
app.py
```

## Development

```bash
python3 -m unittest discover -s tests
python3 -m revinspector samples/example.sh
```

## shadcn/ui note

This project does not use the paid shadcn.io MCP/private registry and does not require `SHADCNIO_TOKEN`.

The current UI is FastAPI + Jinja2 + plain CSS. If the project later adds a React/Tailwind frontend, use the normal open-source shadcn/ui CLI:

```bash
npx shadcn@latest init
npx shadcn@latest add button
```
