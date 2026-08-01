import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:3001";

async function apiFetch(path: string, init?: RequestInit) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  const body = await res.json();
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${JSON.stringify(body)}`);
  }
  return body;
}

function textResult(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

const server = new McpServer({
  name: "items-mcp-server",
  version: "1.0.0",
});

server.registerTool(
  "list_items",
  {
    description: "List all items in the in-memory store",
    inputSchema: {},
  },
  async () => textResult(await apiFetch("/items"))
);

server.registerTool(
  "get_item",
  {
    description: "Get a single item by id",
    inputSchema: { id: z.number().describe("Item id") },
  },
  async ({ id }) => textResult(await apiFetch(`/items/${id}`))
);

server.registerTool(
  "create_item",
  {
    description: "Create a new item",
    inputSchema: {
      name: z.string().describe("Item name"),
      description: z.string().optional().describe("Item description"),
    },
  },
  async ({ name, description }) =>
    textResult(
      await apiFetch("/items", {
        method: "POST",
        body: JSON.stringify({ name, description }),
      })
    )
);

server.registerTool(
  "update_item",
  {
    description: "Update an existing item's name and/or description",
    inputSchema: {
      id: z.number().describe("Item id"),
      name: z.string().optional().describe("New name"),
      description: z.string().optional().describe("New description"),
    },
  },
  async ({ id, name, description }) =>
    textResult(
      await apiFetch(`/items/${id}`, {
        method: "PUT",
        body: JSON.stringify({ name, description }),
      })
    )
);

server.registerTool(
  "delete_item",
  {
    description: "Delete an item by id",
    inputSchema: { id: z.number().describe("Item id") },
  },
  async ({ id }) => textResult(await apiFetch(`/items/${id}`, { method: "DELETE" }))
);

server.registerTool(
  "search_items",
  {
    description: "Search items by a query string matched against name and description",
    inputSchema: { q: z.string().describe("Search query") },
  },
  async ({ q }) => textResult(await apiFetch(`/items/search?q=${encodeURIComponent(q)}`))
);

const transport = new StdioServerTransport();
await server.connect(transport);
