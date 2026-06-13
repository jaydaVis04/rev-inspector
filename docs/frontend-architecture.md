# Frontend Architecture

Rev Inspector currently uses a server-rendered frontend:

- FastAPI routes in `web/app.py`
- Jinja2 templates in `web/templates/`
- Plain CSS in `web/static/style.css`
- Small browser behavior in `web/static/ui.js`

This is intentional. The app is a local static-analysis workbench, and the current UI does not need a React build pipeline.

## shadcn/ui

Do not use the paid shadcn.io MCP/private registry for this project.

Do not use `SHADCNIO_TOKEN`.

If the project later gets a React/Tailwind frontend, use the free open-source shadcn/ui CLI only:

```bash
npx shadcn@latest init
npx shadcn@latest add button
```

Until then, keep shadcn-inspired interaction and component patterns in the existing Jinja/CSS implementation.

## Design target

The UI should remain a professional analyst tool:

- Information-dense.
- Keyboard accessible.
- Semantic HTML.
- Tables for tabular data.
- Clear active states in the left rail.
- Restrained color palette where color maps to status or severity.
