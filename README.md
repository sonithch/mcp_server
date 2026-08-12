# MCP Server — Items API over the Model Context Protocol

A small [Model Context Protocol](https://modelcontextprotocol.io) server built with
[Hono](https://hono.dev), exposing a CRUD "items" store as both a REST API and MCP
tools, with a self-contained OAuth 2.1 authorization server in front of the `/mcp`
endpoint.

**Live URL:** https://mcp-server-z6uu.onrender.com

> Hosted on Render's free tier — the first request after a period of inactivity
> can take ~30-60s to wake the instance up.

## What it does

- **MCP tools** (`list_items`, `get_item`, `create_item`, `create_items`,
  `update_item`, `delete_item`, `search_items`) — callable from any MCP client
  (Claude Desktop, Claude.ai, etc.) against `/mcp`.
- **Plain REST API** — the same CRUD operations under `/items`, for testing or
  non-MCP clients.
- **Built-in OAuth 2.1 server** — implements Dynamic Client Registration (RFC 7591),
  PKCE, and the OAuth discovery endpoints (RFC 8414 / RFC 9728) itself, so any
  MCP client can authenticate without wiring up an external identity provider.
  Approving a request is just clicking "Approve" on a plain consent page — see
  [OAUTH.md](./OAUTH.md) for the full flow and its deliberate trade-offs (this
  is a personal/low-stakes server, not an access-control system).

## Add it as a connector on claude.ai

1. Go to **claude.ai → Settings → Connectors**.
2. Click **Add custom connector**.
3. Paste the server URL: `https://mcp-server-z6uu.onrender.com/mcp`
4. Claude discovers the OAuth endpoints automatically and redirects you to the
   consent page — click **Approve**.
5. The `list_items` / `create_item` / etc. tools are now available in chats
   where this connector is enabled.

The same steps work in Claude Desktop under **Settings → Connectors**.

## Run it locally

```bash
git clone https://github.com/sonithch/mcp_server.git
cd mcp_server
git checkout http-setup
npm install
npm run dev
```

This starts the server on `http://localhost:3001` (override with `PORT`), with:

- `GET /health` — health check
- `GET/POST/PUT/DELETE /items` — REST CRUD
- `POST /mcp` — the MCP endpoint, OAuth-protected

To point an MCP client at your local instance instead, use
`http://localhost:3001/mcp` in step 3 above.

## Deploy

The repo ships a `render.yaml` Blueprint — connect the repo on
[Render](https://render.com), pick "Blueprint", and it deploys the `npm start`
command with a free web service and a `/health` check wired up out of the box.
