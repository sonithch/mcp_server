import { betterAuth } from "better-auth";
import { mcp } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

// better-auth is our OAuth 2.0 / OIDC authorization server for /mcp. Users
// are real - authenticated via Google - rather than the earlier anonymous
// Approve/Reject gate. better-auth owns: Dynamic Client Registration,
// PKCE-enforced /authorize + /token, the consent screen, and the users
// table (SQLite, ./data/auth.db) - we never touch Clerk or any other
// external identity provider.
//
// PUBLIC_URL must be the exact externally-reachable origin (scheme
// included). better-auth needs this as a fixed value up front to construct
// redirect_uris and issuer URLs; unlike our own routes, it doesn't infer it
// per-request from forwarded headers.
const publicUrl = process.env.PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? 3001}`;

const dbPath = process.env.AUTH_DB_PATH ?? "./data/auth.db";
mkdirSync(dirname(dbPath), { recursive: true });

export const auth = betterAuth({
  baseURL: publicUrl,
  basePath: "/api/auth",
  secret: process.env.BETTER_AUTH_SECRET,
  database: new Database(dbPath),
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID ?? "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "",
    },
  },
  plugins: [
    mcp({
      loginPage: "/authorize/login",
      oidcConfig: {
        loginPage: "/authorize/login",
        // The MCP plugin's /authorize only supports consentPage (a redirect
        // target we render ourselves) - its getConsentHTML option exists on
        // the type but is never actually called from this code path, only
        // from the unrelated generic oidc-provider /oauth2/authorize
        // endpoint we don't use.
        consentPage: "/authorize/consent",
      },
    }),
  ],
});

export async function runAuthMigrations() {
  const { runMigrations } = await getMigrations(auth.options);
  await runMigrations();
}
