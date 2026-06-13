# shadcn.io MCP Setup

This project is configured for the shadcn.io remote MCP server through `.codex/config.toml`.

The config intentionally does not contain a token. Export your personal shadcn.io token before starting Codex:

```bash
export SHADCNIO_TOKEN="your-token-here"
```

Then restart Codex from this trusted project. Use prompts like:

```text
use shadcnio to search for dashboard table blocks
use shadcnio to install <block-name> into this project
```

Do not commit real tokens. Use `.env` locally if needed; it is ignored by Git.

Do not run `codex mcp login shadcnio` for this server on this Codex build. It reports `No authorization support detected` because OAuth login is not available for this remote HTTP MCP. The supported path is the bearer token env var above.
