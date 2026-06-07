# Authentik plugin

This [plugin](https://www.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github)
adds [Authentik](https://goauthentik.io/) forward authentication to a
BunkerWeb site. It works on top of any existing service configuration —
reverse proxy, served files, custom location blocks — without replacing them.

The auth check runs from Lua inside BunkerWeb's access phase, so all of
BunkerWeb's built-in checks (rate limit, bad behavior, antibot, DNSBL,
whitelist / blacklist, ...) get to run *before* the Authentik subrequest
fires. Cheap denies stay cheap.

# Table of contents

- [Authentik plugin](#authentik-plugin)
- [Table of contents](#table-of-contents)
- [How it works](#how-it-works)
- [Setup](#setup)
  - [Docker / Swarm](#docker--swarm)
  - [Authentik configuration](#authentik-configuration)
- [Settings](#settings)
- [Notes](#notes)

# How it works

Two pieces:

1. **`authentik.lua` (access phase).** For every request that isn't already
   denied by a higher-priority BunkerWeb check, the handler:
   - skips internal requests and any URI under `AUTHENTIK_OUTPOST_PATH` (so
     the login flow itself is not gated and there's no auth-loop),
   - calls `GET <AUTHENTIK_URL>/outpost.goauthentik.io/auth/nginx` with the
     original cookies, `X-Original-URL`, and `X-Forwarded-*`,
   - on `200` → forwards any returned `Set-Cookie` to the client and lets
     the request continue to its normal destination (reverse proxy / file
     serving / whatever),
   - on `401`/`403` → 302 to `<outpost_path>/start?rd=<original_url>` to
     start the SSO flow.
2. **`confs/server-http/authentik.conf`.** A small server-level snippet that:
   - raises `proxy_buffers` / `proxy_buffer_size` so large Authentik headers
     don't overflow,
   - sets `port_in_redirect off`,
   - adds a `location {{ AUTHENTIK_OUTPOST_PATH }}` block that proxies the
     outpost endpoints (`/auth`, `/start`, `/callback`, `/sign_out`, ...) on
     the protected site's own domain. Keeping these on-domain is what lets
     the proxy provider's session cookie be scoped correctly.

Because authentication is no longer a `auth_request` directive at server
scope, there's no interference with BunkerWeb's `add_header` / `proxy_set_header`
inside `location /`, no antibot redirect loop, and no risk that a
multi-redirect SSO round-trip blocks itself by hitting `bad_behavior` /
`limit_req` ahead of the user's real request — those run first by design.

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github)
of the BunkerWeb documentation for the generic plugin installation procedure.

## Docker / Swarm

```yaml
services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.6.0
    ...
    networks:
      - bw-services
      - bw-authentik
    ...

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0
    ...
    environment:
      SERVER_NAME: "app.example.com"
      USE_REVERSE_PROXY: "yes"
      REVERSE_PROXY_HOST: "http://app:3000"
      REVERSE_PROXY_URL: "/"

      USE_AUTHENTIK: "yes"
      # Embedded outpost on the Authentik server itself:
      AUTHENTIK_URL: "http://authentik-server:9000"
      # Standalone outpost would be e.g. http://authentik-outpost:9000

  authentik-server:
    image: ghcr.io/goauthentik/server:latest
    ...
    networks:
      - bw-authentik

networks:
  bw-services:
    name: bw-services
  bw-authentik:
    name: bw-authentik
```

## Authentik configuration

In the Authentik admin UI:

1. Create a **Proxy Provider** for the protected site. Forward Auth (single
   application) is the most common mode. "External host" should match the
   public URL of the protected site (e.g. `https://app.example.com`).
2. Create or assign an **Application** that uses the provider.
3. Attach the application to an **Outpost** (the built-in *authentik Embedded
   Outpost* works out of the box). `AUTHENTIK_URL` points at this outpost.

# Settings

| Setting                       | Default                  | Context   | Multiple | Description                                                                                              |
| ----------------------------- | ------------------------ | --------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `USE_AUTHENTIK`               | `no`                     | multisite | no       | Activate Authentik forward authentication for this site.                                                 |
| `AUTHENTIK_URL`               | ``                       | multisite | no       | Base URL of the Authentik outpost. The plugin appends `/outpost.goauthentik.io/*` to it.                 |
| `AUTHENTIK_OUTPOST_PATH`      | `/outpost.goauthentik.io`| multisite | no       | Local URL path on the protected site where the outpost endpoints are exposed. Must start with `/`.       |
| `AUTHENTIK_SSL_VERIFY`        | `yes`                    | multisite | no       | Verify the Authentik outpost TLS certificate.                                                            |
| `AUTHENTIK_TIMEOUT`           | `5000`                   | global    | no       | Timeout (ms) for the Lua auth subrequest.                                                                |
| `AUTHENTIK_PROXY_BUFFER_SIZE` | `32k`                    | multisite | no       | `proxy_buffer_size` for this server.                                                                     |
| `AUTHENTIK_PROXY_BUFFERS`     | `8 16k`                  | multisite | no       | `proxy_buffers` for this server.                                                                         |

# Notes

- **Cookie scope.** Keeping `AUTHENTIK_OUTPOST_PATH` on the protected site's
  own domain (rather than redirecting users straight to the Authentik server)
  is what lets the proxy provider's session cookie land on the protected
  domain. Changing the path is fine as long as it's used consistently across
  sites that share a session.
- **Buffer size.** If you see `upstream sent too big header while reading
  response header from upstream`, raise `AUTHENTIK_PROXY_BUFFER_SIZE` /
  `AUTHENTIK_PROXY_BUFFERS`.
- **No identity headers downstream.** This plugin only gates access; it does
  not forward `X-authentik-username` / `-groups` / `-email` to the upstream
  service. If your backend needs to read the SSO identity (Nextcloud, Grafana
  header-auth, ...), file an issue — it's a small addition via
  `ngx.req.set_header`.
- **Per-request cost.** Every gated request makes a single HTTP call to the
  Authentik outpost's `/auth/nginx`. The Authentik outpost itself caches
  session lookups, so this is fast — but keep `AUTHENTIK_URL` pointing at
  something close to BunkerWeb (same Docker network is ideal).
