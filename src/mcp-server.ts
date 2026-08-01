import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  listItems,
  getItem,
  createItem,
  createItems,
  updateItem,
  deleteItem,
  searchItems,
} from "./items-store.js";

function textResult(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

export function createMcpServer() {
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
    async () => textResult(listItems())
  );

  server.registerTool(
    "get_item",
    {
      description: "Get a single item by id",
      inputSchema: { id: z.number().describe("Item id") },
    },
    async ({ id }) => {
      const item = getItem(id);
      if (!item) throw new Error(`Item ${id} not found`);
      return textResult(item);
    }
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
    async ({ name, description }) => textResult(createItem(name, description))
  );

  server.registerTool(
    "create_items",
    {
      description: "Create multiple items at once",
      inputSchema: {
        items: z
          .array(
            z.object({
              name: z.string().describe("Item name"),
              description: z.string().optional().describe("Item description"),
            })
          )
          .describe("Items to create"),
      },
    },
    async ({ items }) => textResult(createItems(items))
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
    async ({ id, name, description }) => {
      const item = updateItem(id, { name, description });
      if (!item) throw new Error(`Item ${id} not found`);
      return textResult(item);
    }
  );

  server.registerTool(
    "delete_item",
    {
      description: "Delete an item by id",
      inputSchema: { id: z.number().describe("Item id") },
    },
    async ({ id }) => {
      const item = deleteItem(id);
      if (!item) throw new Error(`Item ${id} not found`);
      return textResult(item);
    }
  );

  server.registerTool(
    "search_items",
    {
      description: "Search items by a query string matched against name and description",
      inputSchema: { q: z.string().describe("Search query") },
    },
    async ({ q }) => textResult(searchItems(q))
  );

  return server;
}
