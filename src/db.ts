import postgres from "postgres";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes } from "node:crypto";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is not set - the OAuth server needs Postgres to persist client registrations");
}

// Supabase's transaction pooler (port 6543) hands out a different backend
// connection per transaction, so server-side prepared statements can't be
// relied on - postgres.js has to be told not to use them. Without this you
// get intermittent "prepared statement ... does not exist" errors under
// concurrency rather than a clean failure at boot.
export const sql = postgres(databaseUrl, {
  prepare: false,
  max: 5,
  idle_timeout: 20,
});

export async function migrate(): Promise<void> {
  const path = fileURLToPath(new URL("./migrations/001_oauth.sql", import.meta.url));
  await sql.unsafe(readFileSync(path, "utf8"));
}

// Tokens are compared by hash, never stored in the clear: a read-only leak
// of the database shouldn't hand over anything replayable.
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function newSecret(): string {
  return randomBytes(32).toString("base64url");
}

// Deletes rows that are past their usefulness. Expired-but-present rows are
// harmless (every read filters on expires_at); this just stops the tables
// from growing forever on abandoned flows.
export async function sweepExpired(): Promise<void> {
  await sql`delete from oauth_auth_requests where expires_at < now()`;
  await sql`delete from oauth_auth_codes where expires_at < now() - interval '1 day'`;
  await sql`delete from oauth_refresh_tokens where expires_at < now() - interval '30 days'`;
}
