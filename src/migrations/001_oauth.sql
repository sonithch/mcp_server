-- OAuth 2.0 authorization server state.
--
-- Everything here exists so that a restart (or a second instance, or a
-- free-tier cold start) is invisible to an already-connected client.
-- Access tokens are deliberately NOT stored: they're stateless JWTs
-- verified by signature. What must survive is the state a client can't
-- reconstruct on its own - its registration, and its refresh token.

-- Dynamic Client Registration (RFC 7591). The registration access token
-- is stored hashed so a database leak can't be replayed against the
-- RFC 7592 management endpoints.
create table if not exists oauth_clients (
  client_id                        uuid primary key,
  client_name                      text,
  redirect_uris                    text[]      not null,
  registration_access_token_hash   text        not null,
  created_at                       timestamptz not null default now()
);

-- In-flight /authorize requests, between rendering the consent page and
-- the user clicking a button. Short-lived; persisted so a restart
-- mid-flow doesn't strand the browser redirect.
create table if not exists oauth_auth_requests (
  request_id     uuid primary key,
  client_id      uuid        not null references oauth_clients(client_id) on delete cascade,
  redirect_uri   text        not null,
  code_challenge text        not null,
  state          text,
  scope          text        not null default '',
  expires_at     timestamptz not null
);

-- Authorization codes. Stored hashed and single-use: `consumed_at` is set
-- on redemption rather than deleting the row, so a replayed code is
-- distinguishable from an unknown one.
create table if not exists oauth_auth_codes (
  code_hash      text primary key,
  client_id      uuid        not null references oauth_clients(client_id) on delete cascade,
  redirect_uri   text        not null,
  code_challenge text        not null,
  scope          text        not null default '',
  expires_at     timestamptz not null,
  consumed_at    timestamptz
);

-- A user's standing consent for a client. Lets a returning client skip
-- the approval page, and gives us something to revoke.
create table if not exists oauth_grants (
  grant_id   uuid primary key,
  client_id  uuid        not null unique references oauth_clients(client_id) on delete cascade,
  scope      text        not null default '',
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

-- Refresh tokens, hashed, rotated on every use. `rotated_to` records the
-- successor so that replaying a rotated token is detectable - the standard
-- signal that a token was stolen, at which point the whole grant dies.
create table if not exists oauth_refresh_tokens (
  token_hash text primary key,
  grant_id   uuid        not null references oauth_grants(grant_id) on delete cascade,
  client_id  uuid        not null references oauth_clients(client_id) on delete cascade,
  scope      text        not null default '',
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  rotated_to text
);

create index if not exists oauth_auth_requests_expires_at_idx  on oauth_auth_requests (expires_at);
create index if not exists oauth_auth_codes_expires_at_idx     on oauth_auth_codes (expires_at);
create index if not exists oauth_refresh_tokens_grant_id_idx   on oauth_refresh_tokens (grant_id);
