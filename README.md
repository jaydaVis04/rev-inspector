# Rev Inspector

Rev Inspector is a static binary inspection assistant for learning defensive reverse engineering and malware-analysis concepts without executing unknown samples.

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

## Optional web UI

```bash
pip install -e ".[web]"
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000` and upload a sample for static inspection. The server writes uploads to a temporary file only long enough to analyze them and never executes them.

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
