# shadcn.io MCP Setup

This project is configured for the shadcn.io remote MCP server through `.codex/config.toml`.

The config intentionally does not contain a token. Export your personal bearer token before starting Codex:

```bash
export SHADCNIO_BEARER="Bearer $SHADCNIO_TOKEN"
```

Then restart Codex from this trusted project. Use prompts like:

```text
use shadcnio to search for dashboard table blocks
use shadcnio to install <block-name> into this project
```

Do not commit real tokens. Use `.env` locally if needed; it is ignored by Git.
