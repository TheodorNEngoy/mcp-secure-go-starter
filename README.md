# mcp-secure-go-starter

Secure-by-default Go starter for Model Context Protocol (MCP) servers (streamable HTTP).

What this template prioritizes:

- CORS **allowlist** (no wildcard origins)
- Request body size limits
- Optional bearer token auth
- Small tool surface area by default
- CI gate with `mcp-safety-scanner`

## Run

Prereqs: Go 1.22+.

```bash
go run ./cmd/server
```

The server listens on `http://127.0.0.1:8000/` and exposes a basic health check at `http://127.0.0.1:8000/healthz`.

## Configuration

Copy `.env.example` to `.env` and export the values in your shell (this template stays dependency-free).

Key env vars:

- `MCP_CORS_ALLOW_ORIGINS`: comma-separated origin allowlist
- `MCP_MAX_BODY_BYTES`: request size limit (default: 256KiB)
- `MCP_AUTH_TOKEN`: if set, requires `Authorization: Bearer ...`

## Add Tools Safely

Before adding a tool:

- Decide what inputs can be attacker-controlled.
- Add strict input schemas and allowlists.
- Put hard limits on size/time/records.
- Avoid shell execution (`sh -c`, `cmd /c`, etc.).
