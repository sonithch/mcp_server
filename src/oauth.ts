import { Hono } from "hono";
import { randomBytes, createHash } from "node:crypto";
import { createClerkClient } from "@clerk/backend";

// OAuth 2.1 authorization server implementing just enough of RFC 8414
// (metadata), RFC 7591 (dynamic client registration), RFC 9728 (protected
// resource metadata), and authorization-code + PKCE for the MCP
// authorization spec. End-user identity for the consent screen is delegated
// to Clerk - any signed-up Clerk user can approve an authorization request.

const clerkClient =
  process.env.CLERK_SECRET_KEY && process.env.CLERK_PUBLISHABLE_KEY
    ? createClerkClient({
        secretKey: process.env.CLERK_SECRET_KEY,
        publishableKey: process.env.CLERK_PUBLISHABLE_KEY,
      })
    : undefined;

// Clerk's Account Portal (hosted sign-in/sign-up) host is derived from the
// publishable key: pk_<env>_<base64(frontendApiHost + "$")>. The frontend
// API host is "<slug>.clerk.accounts.dev"; the Account Portal for the same
// instance drops the ".clerk" segment: "<slug>.accounts.dev".
function clerkAccountPortalUrl(publishableKey: string, path: "sign-in" | "sign-up") {
  const encoded = publishableKey.split("_")[2] ?? "";
  const padded = encoded + "=".repeat((4 - (encoded.length % 4)) % 4);
  const frontendApiHost = Buffer.from(padded, "base64").toString("utf8").replace(/\$$/, "");
  const accountPortalHost = frontendApiHost.replace(/^([^.]+)\.clerk\./, "$1.");
  return `https://${accountPortalHost}/${path}`;
}

const clerkSignInUrl = process.env.CLERK_PUBLISHABLE_KEY
  ? clerkAccountPortalUrl(process.env.CLERK_PUBLISHABLE_KEY, "sign-in")
  : undefined;

interface Client {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: "client_secret_post" | "none";
}

interface PendingAuthorization {
  client_id: string;
  redirect_uri: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: string;
  resource?: string;
  user_id: string;
}

interface AuthCode extends PendingAuthorization {
  expiresAt: number;
}

interface IssuedToken {
  client_id: string;
  user_id: string;
  expiresAt: number;
}

const clients = new Map<string, Client>();
const pendingAuthorizations = new Map<string, PendingAuthorization>();
const authCodes = new Map<string, AuthCode>();
const accessTokens = new Map<string, IssuedToken>();
const refreshTokens = new Map<string, IssuedToken>();

const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;
const AUTH_CODE_TTL_MS = 60 * 1000;

function token(bytes = 32) {
  return randomBytes(bytes).toString("hex");
}

function base64url(input: Buffer) {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function verifyPkce(codeVerifier: string, codeChallenge: string, method: string) {
  if (method !== "S256") return false;
  const hash = createHash("sha256").update(codeVerifier).digest();
  return base64url(hash) === codeChallenge;
}

export function isValidAccessToken(bearerToken: string): boolean {
  const issued = accessTokens.get(bearerToken);
  if (!issued) return false;
  if (issued.expiresAt < Date.now()) {
    accessTokens.delete(bearerToken);
    return false;
  }
  return true;
}

export function createOAuthRoutes(baseUrl: string) {
  const oauth = new Hono();

  // RFC 8414 - Authorization Server Metadata
  oauth.get("/.well-known/oauth-authorization-server", (c) =>
    c.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      registration_endpoint: `${baseUrl}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    })
  );

  // RFC 9728 - Protected Resource Metadata (for the /mcp resource)
  oauth.get("/.well-known/oauth-protected-resource", (c) =>
    c.json({
      resource: `${baseUrl}/mcp`,
      authorization_servers: [baseUrl],
    })
  );

  // RFC 7591 - Dynamic Client Registration
  oauth.post("/register", async (c) => {
    const body = await c.req.json<{
      redirect_uris?: string[];
      client_name?: string;
      token_endpoint_auth_method?: string;
    }>();

    if (!body.redirect_uris?.length) {
      return c.json({ error: "invalid_client_metadata", error_description: "redirect_uris is required" }, 400);
    }

    const client_id = token(16);
    const authMethod = body.token_endpoint_auth_method === "none" ? "none" : "client_secret_post";
    const client: Client = {
      client_id,
      client_secret: authMethod === "none" ? undefined : token(32),
      redirect_uris: body.redirect_uris,
      token_endpoint_auth_method: authMethod,
    };
    clients.set(client_id, client);

    return c.json(
      {
        client_id: client.client_id,
        client_secret: client.client_secret,
        redirect_uris: client.redirect_uris,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
      },
      201
    );
  });

  // Authorization endpoint - gated by a Clerk session; any signed-up Clerk
  // user can approve.
  oauth.get("/authorize", async (c) => {
    if (!clerkClient) return c.text("Server misconfigured: CLERK_SECRET_KEY / CLERK_PUBLISHABLE_KEY not set", 500);

    const requestState = await clerkClient.authenticateRequest(c.req.raw, {
      authorizedParties: [baseUrl, new URL(baseUrl).origin],
    });

    if (requestState.status === "handshake") {
      return new Response(null, { status: 307, headers: requestState.headers });
    }

    if (requestState.status !== "signed-in") {
      const signInUrl = new URL(requestState.signInUrl || clerkSignInUrl || "");
      signInUrl.searchParams.set("redirect_url", c.req.url);
      return c.redirect(signInUrl.toString());
    }

    const { userId } = requestState.toAuth();

    const client_id = c.req.query("client_id") ?? "";
    const redirect_uri = c.req.query("redirect_uri") ?? "";
    const state = c.req.query("state");
    const code_challenge = c.req.query("code_challenge") ?? "";
    const code_challenge_method = c.req.query("code_challenge_method") ?? "";
    const resource = c.req.query("resource");
    const response_type = c.req.query("response_type");

    const client = clients.get(client_id);
    if (!client) return c.text("Unknown client_id", 400);
    if (!client.redirect_uris.includes(redirect_uri)) {
      return c.text("redirect_uri does not match a registered redirect URI", 400);
    }
    if (response_type !== "code") {
      return c.text("Only response_type=code is supported", 400);
    }
    if (!code_challenge || code_challenge_method !== "S256") {
      return c.text("PKCE with S256 is required", 400);
    }

    const requestId = token(16);
    pendingAuthorizations.set(requestId, {
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      resource,
      user_id: userId,
    });

    let identity = userId;
    try {
      const user = await clerkClient.users.getUser(userId);
      identity = user.primaryEmailAddress?.emailAddress ?? userId;
    } catch {
      // fall back to userId if the lookup fails
    }

    return c.html(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Authorize</title>
<style>body{font-family:system-ui,sans-serif;max-width:420px;margin:80px auto;padding:0 20px}
button{padding:10px 20px;margin-right:10px;font-size:15px;cursor:pointer}
.approve{background:#111;color:#fff;border:none;border-radius:6px}
.deny{background:none;border:1px solid #ccc;border-radius:6px}</style>
</head>
<body>
  <h2>Authorize access</h2>
  <p>Signed in as <strong>${identity}</strong>.</p>
  <p>An application is requesting access to the items MCP server.</p>
  <form method="POST" action="/authorize/approve">
    <input type="hidden" name="request_id" value="${requestId}" />
    <button class="approve" type="submit">Approve</button>
    <button class="deny" formaction="/authorize/deny" formnovalidate type="submit">Deny</button>
  </form>
</body>
</html>`);
  });

  oauth.post("/authorize/approve", async (c) => {
    if (!clerkClient) return c.text("Server misconfigured: CLERK_SECRET_KEY / CLERK_PUBLISHABLE_KEY not set", 500);

    const requestState = await clerkClient.authenticateRequest(c.req.raw, {
      authorizedParties: [baseUrl, new URL(baseUrl).origin],
    });
    if (requestState.status !== "signed-in") {
      return c.text("Not signed in", 401);
    }

    const body = await c.req.parseBody();
    const requestId = String(body.request_id ?? "");
    const pending = pendingAuthorizations.get(requestId);
    if (!pending) return c.text("Authorization request not found or expired", 400);
    if (pending.user_id !== requestState.toAuth().userId) {
      return c.text("This authorization request belongs to a different user", 403);
    }

    pendingAuthorizations.delete(requestId);

    const code = token(32);
    authCodes.set(code, { ...pending, expiresAt: Date.now() + AUTH_CODE_TTL_MS });

    const redirect = new URL(pending.redirect_uri);
    redirect.searchParams.set("code", code);
    if (pending.state) redirect.searchParams.set("state", pending.state);
    return c.redirect(redirect.toString());
  });

  oauth.post("/authorize/deny", async (c) => {
    const body = await c.req.parseBody();
    const requestId = String(body.request_id ?? "");
    const pending = pendingAuthorizations.get(requestId);
    if (!pending) return c.text("Authorization request not found or expired", 400);
    pendingAuthorizations.delete(requestId);

    const redirect = new URL(pending.redirect_uri);
    redirect.searchParams.set("error", "access_denied");
    if (pending.state) redirect.searchParams.set("state", pending.state);
    return c.redirect(redirect.toString());
  });

  // Token endpoint - authorization_code and refresh_token grants
  oauth.post("/token", async (c) => {
    const body = await c.req.parseBody();
    const grant_type = String(body.grant_type ?? "");

    const authHeader = c.req.header("Authorization");
    let client_id = String(body.client_id ?? "");
    let client_secret = typeof body.client_secret === "string" ? body.client_secret : undefined;
    if (authHeader?.startsWith("Basic ")) {
      const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
      const [basicId, basicSecret] = decoded.split(":");
      client_id = client_id || basicId;
      client_secret = client_secret ?? basicSecret;
    }

    const client = clients.get(client_id);
    if (!client) return c.json({ error: "invalid_client" }, 401);
    if (client.token_endpoint_auth_method === "client_secret_post" && client.client_secret !== client_secret) {
      return c.json({ error: "invalid_client" }, 401);
    }

    if (grant_type === "authorization_code") {
      const code = String(body.code ?? "");
      const authCode = authCodes.get(code);
      if (!authCode || authCode.client_id !== client_id) {
        return c.json({ error: "invalid_grant" }, 400);
      }
      authCodes.delete(code);
      if (authCode.expiresAt < Date.now()) {
        return c.json({ error: "invalid_grant", error_description: "code expired" }, 400);
      }
      if (String(body.redirect_uri ?? "") !== authCode.redirect_uri) {
        return c.json({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, 400);
      }
      const codeVerifier = String(body.code_verifier ?? "");
      if (!verifyPkce(codeVerifier, authCode.code_challenge, authCode.code_challenge_method)) {
        return c.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
      }

      const access_token = token(32);
      const refresh_token = token(32);
      const expiresAt = Date.now() + ACCESS_TOKEN_TTL_MS;
      accessTokens.set(access_token, { client_id, user_id: authCode.user_id, expiresAt });
      refreshTokens.set(refresh_token, { client_id, user_id: authCode.user_id, expiresAt: Infinity });

      return c.json({
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_MS / 1000,
        refresh_token,
      });
    }

    if (grant_type === "refresh_token") {
      const refresh_token = String(body.refresh_token ?? "");
      const issued = refreshTokens.get(refresh_token);
      if (!issued || issued.client_id !== client_id) {
        return c.json({ error: "invalid_grant" }, 400);
      }

      const access_token = token(32);
      const expiresAt = Date.now() + ACCESS_TOKEN_TTL_MS;
      accessTokens.set(access_token, { client_id, user_id: issued.user_id, expiresAt });

      return c.json({
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_MS / 1000,
        refresh_token,
      });
    }

    return c.json({ error: "unsupported_grant_type" }, 400);
  });

  return oauth;
}
