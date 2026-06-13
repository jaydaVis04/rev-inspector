# Rev Inspector Agent Instructions

## Product scope

Rev Inspector is a defensive, static-analysis reverse-engineering assistant.

- Static analysis only.
- Never execute uploaded or unknown samples.
- Keep upload handling local and explicit.
- Do not add unpacking, evasion, exploitation, or bypass workflows.

## Frontend architecture

The current web UI is FastAPI + Jinja2 + plain CSS:

- `web/app.py`
- `web/templates/`
- `web/static/style.css`
- `web/static/ui.js`

Keep that stack unless the user explicitly asks to add a React frontend.

## shadcn/ui rule

Do not use paid shadcn.io MCP, private registry, or `SHADCNIO_TOKEN`.

If a future React/Tailwind frontend is explicitly added, use only the free open-source shadcn/ui CLI:

```bash
npx shadcn@latest init
npx shadcn@latest add <component>
```

Do not add `.codex/config.toml` for shadcn.io MCP unless the user explicitly provides a paid/private registry requirement.

## UI direction

The UI should feel like a professional static-analysis workbench:

- Dense, readable, table-first.
- Topbar + left rail + main workspace.
- No hacker-movie terminal decoration, neon glow, particle effects, or marketing hero copy.
- Use color for meaning: severity, status, focus, and active state.
- Keep copy direct and operational.

## Verification

Before committing code changes, run:

```bash
python3 -m unittest discover -s tests
```

When web dependencies are available, also run:

```bash
.venv/bin/python -m unittest discover -s tests
```
