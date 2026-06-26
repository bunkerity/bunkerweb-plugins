# Coraza plugin

![BunkerWeb plugins version](https://img.shields.io/badge/bunkerweb_plugins-1.11-blue)

```mermaid
flowchart TD
    accTitle: BunkerWeb Coraza plugin request flow
    accDescr: A client request first passes BunkerWeb core checks, then coraza.lua forwards the request metadata and body as JSON over HTTP to the Coraza Go sidecar. The sidecar evaluates the OWASP Core Rule Set and returns a verdict. A disrupted verdict denies the request, otherwise it reaches the upstream.

    client([Client / Browser])

    subgraph bw[BunkerWeb access phase]
        direction TB
        core["1. Core checks first:<br/>rate limit, bad behavior, antibot,<br/>DNSBL, black / whitelist"]
        lua["2. coraza.lua:<br/>read body, build X-Coraza-* JSON,<br/>POST CORAZA_API + /request"]
        core --> lua
    end

    subgraph sidecar[Coraza Go service - coraza/api]
        direction TB
        api[["HTTP API:<br/>/ping (health), /request"]]
        crs[("OWASP CRS<br/>vendored at build")]
        api --- crs
    end

    verdict{"disrupted?"}
    allow["Allow to upstream"]
    deny["Deny request<br/>(get_deny_status)"]
    upstream([Upstream app])

    client -->|request| core
    lua -.->|"request JSON over HTTP"| api
    api -.->|verdict| verdict
    verdict -->|"yes (rule matched)"| deny
    verdict -->|no| allow
    allow --> upstream

    classDef ok fill:#eafaf0,stroke:#27ae60,color:#14532d;
    classDef deny fill:#fdecea,stroke:#e74c3c,color:#7f1d1d;
    classDef svc fill:#e8f4fd,stroke:#2980b9,color:#0c4a6e;
    classDef app fill:#ffffff,stroke:#334155,color:#0f172a;
    class allow,upstream ok;
    class deny deny;
    class api,crs svc;
    class client,core,lua app;
```

This [plugin](https://www.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github)
runs the [Coraza](https://coraza.io/) web application firewall - a Go
reimplementation of the ModSecurity engine - loaded with the
[OWASP Core Rule Set](https://coreruleset.org/) (CRS), to detect and block
malicious requests before they reach the upstream. Unlike every other plugin
in this repository, Coraza relies on an **external sidecar**: a standalone Go
HTTP service (the `bunkerity/bunkerweb-coraza` image, built from `coraza/api/`)
that wraps `corazawaf/coraza/v3` and bakes the CRS in at build time.

The inspection runs from Lua during BunkerWeb's access phase, so all of
BunkerWeb's built-in checks (rate limit, bad behavior, antibot, DNSBL,
whitelist / blacklist, ...) run _before_ the request is handed to Coraza.
For each request `coraza.lua` reads the full body, builds a set of
`X-Coraza-*` metadata headers, and `POST`s the request to the sidecar's
`/request` endpoint; the sidecar evaluates the request headers and body
against the CRS and returns a `{"deny": bool, "msg": string}` verdict. A
disrupting verdict denies the request with BunkerWeb's deny status.

# Table of contents

- [Coraza plugin](#coraza-plugin)
- [Table of contents](#table-of-contents)
- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Docker / Swarm](#docker--swarm)
- [Settings](#settings)
- [Troubleshooting](#troubleshooting)
- [Notes](#notes)

# How it works

1. BunkerWeb's access-phase checks run (rate limit, bad behavior, antibot,
   DNSBL, blacklist, ...). If any of them deny, the request stops here and
   Coraza is never consulted.
2. At worker startup, `init_worker` sends `GET <CORAZA_API>/ping` as a health
   check. If the sidecar does not answer with a valid `pong` JSON, the failure
   is logged.
3. On each request, `coraza.lua` reads the full request body and builds the
   metadata headers `X-Coraza-Version`, `X-Coraza-Method`, `X-Coraza-Ip`,
   `X-Coraza-Id` (a random transaction id) and `X-Coraza-Uri`, plus every
   incoming request header re-emitted as `X-Coraza-Header-<name>`. It then
   `POST`s the body to `<CORAZA_API>/request`.
4. The sidecar opens a Coraza transaction and evaluates two phases - first the
   request headers, then the request body - against, in order, `coraza.conf`,
   `bunkerweb.conf`, `/rules-before/*.conf`, the CRS (`crs-setup.conf.example`
   then `rules/*.conf`), and `/rules-after/*.conf`. It replies with
   `{"deny": bool, "msg": string}`.
5. If the verdict is `deny: true` (a rule triggered a disrupting action -
   `block`, `deny`, `drop`, `redirect` or `reject`), the request is denied with
   `utils.get_deny_status()` and the rule message is attached. Otherwise the
   request continues to its normal destination.
6. If the sidecar is unreachable or returns a non-`200` status, the request is
   denied with HTTP `500` and the error is logged - Coraza **fails closed**.

# Prerequisites

The Coraza sidecar must be deployed and reachable from BunkerWeb at the URL
configured in `CORAZA_API`. Use the official `bunkerity/bunkerweb-coraza`
image and attach the sidecar to a network shared with the BunkerWeb
container (the examples below use a dedicated `bw-plugins` network). The
sidecar listens on port `8080` and bundles the OWASP CRS, so no separate rule
download is needed.

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github)
of the BunkerWeb documentation for the generic plugin installation procedure
(the short version: drop the `coraza/` directory into the scheduler's
`/data/plugins/` and restart).

## Docker / Swarm

`CORAZA_API` is the URL BunkerWeb uses to reach the sidecar - typically an
internal Docker network address. Keep `HTTP2` disabled and the core
ModSecurity WAF (`USE_MODSECURITY`) off so you don't run two WAFs at once.

```yaml
services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.6.11
    ...
    networks:
      - bw-services
      - bw-plugins
    ...

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.11
    ...
    environment:
      SERVER_NAME: "app.example.com"
      USE_REVERSE_PROXY: "yes"
      REVERSE_PROXY_HOST: "http://app:3000"
      REVERSE_PROXY_URL: "/"

      HTTP2: "no" # The Coraza plugin does not support HTTP/2 yet
      USE_MODSECURITY: "no" # Run Coraza instead of the core ModSecurity WAF
      USE_CORAZA: "yes"
      # Internal URL - what BunkerWeb uses to call the Coraza sidecar:
      CORAZA_API: "http://bw-coraza:8080"

  bw-coraza:
    image: bunkerity/bunkerweb-coraza:1.6.11
    networks:
      - bw-plugins

networks:
  bw-services:
    name: bw-services
  bw-plugins:
    name: bw-plugins
```

# Settings

| Setting      | Default                 | Context   | Multiple | Description                                                                            |
| ------------ | ----------------------- | --------- | -------- | -------------------------------------------------------------------------------------- |
| `USE_CORAZA` | `no`                    | multisite | no       | Activate the Coraza WAF (OWASP Core Rule Set evaluation) for this site.                |
| `CORAZA_API` | `http://bw-coraza:8080` | global    | no       | Base URL (scheme + host + port) of the Coraza WAF sidecar, e.g. http://bw-coraza:8080. |

# Troubleshooting

- **Every request returns HTTP 500.** The sidecar is unreachable or answering
  with a non-`200` status. Coraza fails closed, so a down sidecar blocks all
  traffic. Check that `bw-coraza` is running, on the shared network, and that
  `CORAZA_API` points at it (scheme + host + port `8080`). The scheduler log
  shows the underlying error.
- **HTTP/2 sites misbehave.** The plugin does not support HTTP/2 yet; keep
  `HTTP2: "no"`.
- **Requests are inspected twice / unexpected WAF blocks.** You are likely
  running both Coraza and the core ModSecurity WAF. Set `USE_MODSECURITY: "no"`
  so only Coraza evaluates the request.
- **A legitimate request is blocked by a CRS rule.** Add your own rule
  overrides (e.g. `SecRuleRemoveById`, exclusions, paranoia-level tuning) as
  `.conf` files and mount them into the sidecar at `/rules-before/` (evaluated
  before the CRS) or `/rules-after/` (evaluated after it). The rule message in
  the deny reason identifies which rule fired.
- **CRS feels outdated.** The Core Rule Set is pinned and baked into the image
  at build time. Updating it means rebuilding `bunkerity/bunkerweb-coraza`, not
  restarting BunkerWeb (see Notes).

# Notes

- **External sidecar required.** This is the only plugin that depends on a
  separate service. The `bunkerity/bunkerweb-coraza` container must be deployed
  alongside BunkerWeb and reachable at `CORAZA_API`. There is no in-process
  fallback.
- **Fail-closed by design.** If the sidecar cannot be reached or returns a
  non-`200` response, the request is denied (HTTP `500`). This avoids letting
  traffic through unscanned, at the cost of coupling availability to the
  sidecar - keep it healthy and close to BunkerWeb (same Docker network is
  ideal).
- **CRS is pinned and baked into the image.** The OWASP Core Rule Set is
  vendored at build time by `coraza/api/crs.sh`, pinned to a commit hash with
  its `.git` stripped, and compiled into the image. Bumping the CRS version
  means bumping that hash and rebuilding `bunkerity/bunkerweb-coraza` - a plain
  BunkerWeb restart will not pick up a newer rule set.
- **HTTP/2 not yet supported.** Disable HTTP/2 on protected sites
  (`HTTP2: "no"`) while using this plugin.
