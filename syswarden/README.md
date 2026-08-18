# SysWarden plugin

![BunkerWeb plugins version](https://img.shields.io/badge/bunkerweb_plugins-1.11-blue)

```mermaid
flowchart TD
    accTitle: BunkerWeb SysWarden plugin
    accDescr: BunkerWeb inspects traffic at Layer 7 and bans attackers. The scheduler pushes those bans to SysWarden's HA API, which loads them into an nftables set so the same attacker is dropped in the kernel for every service on the host, containers included. In the other direction the scheduler downloads SysWarden's blocklist and whitelist so BunkerWeb can also deny those peers at Layer 7, and polls status and telemetry for the web UI.

    visitor([Visitor])

    subgraph host[Docker host]
        direction TB
        nft{"nftables inet syswarden<br/>docker_protect, hook forward<br/>saddr or daddr in @banned_ips<br/>or @syswarden_blacklist?"}
        subgraph bw[BunkerWeb]
            direction TB
            l7["Core checks, then syswarden.lua<br/>access / preread:<br/>whitelist first, then blocklist"]
        end
    end

    drop["Dropped in the kernel<br/>no packet reaches nginx"]
    deny["403 or connection closed"]
    upstream([Upstream app])

    subgraph sched[BunkerWeb scheduler jobs]
        direction TB
        push["syswarden-ban-push<br/>every minute"]
        pull["syswarden-blocklist-download<br/>every hour"]
        tel["syswarden-telemetry-poll<br/>every minute"]
    end

    swapi[["SysWarden HA API<br/>TLS 1.3 on :62026"]]
    ui([BunkerWeb web UI])

    visitor -->|packet| nft
    nft -->|in blacklist| drop
    nft -->|not in blacklist| l7
    l7 -->|allowed| upstream
    l7 -->|blocked| deny

    l7 -.->|ban recorded| push
    push -.->|"POST and DELETE /ha/sync"| swapi
    swapi -.->|loads the nft set| nft
    pull -.->|"GET /ha/sync and /ha/telemetry"| swapi
    pull -.->|blocklist.list, whitelist.list| l7
    tel -.->|"GET /ha/status and /ha/telemetry"| swapi
    tel -.->|telemetry.json| ui

    classDef ok fill:#eafaf0,stroke:#27ae60,color:#14532d;
    classDef deny fill:#fdecea,stroke:#e74c3c,color:#7f1d1d;
    classDef swc fill:#eef2ff,stroke:#4f46e5,color:#312e81;
    classDef app fill:#ffffff,stroke:#334155,color:#0f172a;
    class upstream ok;
    class drop,deny deny;
    class swapi swc;
    class visitor,nft,l7,push,pull,tel,ui app;
```

This [plugin](https://www.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github)
bridges BunkerWeb and [SysWarden](https://github.com/duggytuxy/syswarden), the host
security orchestrator that owns nftables on your server. BunkerWeb sees the
whole request and decides who to ban; SysWarden drops packets in the kernel for the whole
host. The plugin makes each one act on what the other knows: a BunkerWeb ban becomes a
kernel drop within a minute, and SysWarden's blocklist becomes a Layer 7 deny.

Because SysWarden hooks `forward` (its `docker_protect` chain) and not only `input`, a
pushed ban also covers traffic destined to your containers — which is what makes this
useful for a Dockerised BunkerWeb.

The plugin talks to SysWarden's HA API over TLS and never writes to its files, so
SysWarden stays the only owner of its own state.

# Table of contents

- [SysWarden plugin](#syswarden-plugin)
- [Table of contents](#table-of-contents)
- [How it works](#how-it-works)
  - [Ownership: what the plugin will and will not delete](#ownership-what-the-plugin-will-and-will-not-delete)
- [Prerequisites](#prerequisites)
  - [SysWarden side](#syswarden-side)
  - [TLS](#tls)
- [Setup](#setup)
  - [Docker](#docker)
  - [Linux](#linux)
- [Secrets](#secrets)
- [Settings](#settings)
- [Troubleshooting](#troubleshooting)
- [Notes](#notes)

# How it works

The plugin has two halves: scheduler jobs that talk to SysWarden, and per-request Lua
hooks in the BunkerWeb instance.

**Scheduler jobs (declared in `plugin.json`, scripts under `jobs/`):**

| Job                            | Schedule     | What it does                                                                                                                                                   |
| ------------------------------ | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `syswarden-ban-push`           | every minute | Reads BunkerWeb's active bans (Redis when enabled, plus `GET /bans` on every instance), then reconciles each peer's blocklist with `POST` / `DELETE /ha/sync`. |
| `syswarden-blocklist-download` | hourly       | Downloads each peer's blocklist (`GET /ha/sync`) and whitelist (`GET /ha/telemetry`) into `blocklist.list` / `whitelist.list`, which the Lua side denies on.   |
| `syswarden-telemetry-poll`     | every minute | Polls `GET /ha/status` and `GET /ha/telemetry` per peer into `telemetry.json`, which feeds the web UI cards. Writes only when something changed.               |

**Per request (`syswarden.lua`), when `USE_SYSWARDEN_BLOCKLIST` or `USE_SYSWARDEN_WHITELIST` is on for the service:**

1. At `init`, the downloaded lists are read once and stored in the datastore; each worker
   compiles them at startup to surface a malformed list early.
2. In the `access` phase (and `preread` for stream services) the client address is checked
   against the **whitelist first**, then the blocklist. An address in both is allowed: the
   whitelist is the operator's explicit override, a blocklist hit is a policy default.
3. The verdict is cached per server for an hour, matching the default download interval so a
   released address is not denied for longer than the list it came from.

Both halves are independent: you can push bans without ever downloading a list, and the
other way round.

## Ownership: what the plugin will and will not delete

`/ha/sync` writes into SysWarden's **shared** blocklist, next to entries added by an
operator (`syswarden block`) and by real HA peers. The push job never deletes an entry it
did not add itself, whatever else changes. How it knows depends on what the peer supports.
It asks each peer on every pass, through the `capabilities` list in `GET /ha/status`, so a
cluster can be upgraded one host at a time.

**Peers that report `sync_provenance`.** Each pushed ban carries a lifetime, the BunkerWeb
ban reason, and the source tag from `SYSWARDEN_BAN_SOURCE` (`bunkerweb` by default).
SysWarden keys its ledger on `(address, source, peer scope)` and only deletes records
matching all three, so `GET /ha/sync?details=true` gives the plugin back exactly its own
entries. The peer holds the ownership, which survives a lost job cache. These bans also
expire on their own: the lifetime sent is the ban's remaining time, capped at 30 days for a
permanent BunkerWeb ban. A ban that simply runs out therefore needs no call at all — the
plugin only deletes when BunkerWeb lifts a ban early.

**Older peers, and peers with `[integrations.bunkerweb]` off.** Without provenance the
plugin keeps its own registry of what it pushed (`pushed.json` in the job cache) and only
deletes an entry that is _in the registry_ and no longer banned in BunkerWeb. Bans pushed
this way are permanent on the SysWarden side until the plugin removes them. Only what was
pushed successfully enters the registry, so a failed push never grants ownership of an
entry the plugin did not actually write.

**Upgrading a peer.** The two stores are disjoint on the SysWarden side: entries pushed in
the legacy dialect live in the static blocklist and are only reachable through that same
dialect. So when a peer starts reporting provenance, the plugin keeps reconciling the
entries it wrote before, and removes them with the legacy payload once BunkerWeb stops
banning them. Without that they would stay blocked in the kernel forever.

**Clusters that replicate between themselves.** SysWarden peers can sync their static
blocklist to each other with their own ha-sync, so an entry the plugin deletes on one peer
can be pushed back by another between two requests of the same pass. The plugin therefore
releases ownership of an address only after a full pass in which no peer reports it any
more and BunkerWeb no longer bans it, never on the delete receipt alone. A resurrected
entry is seen again on the next pass and deleted again. This only closes if
`SYSWARDEN_PEERS` lists **every** peer of the cluster: a peer the plugin cannot see keeps
re-seeding entries it will never be asked to drop.

In every case, if a `DELETE` fails on one peer the entry stays in the registry so the next
pass retries it, rather than orphaning it in that peer's blocklist. And an address the
`SYSWARDEN_BAN_MAX_ITEMS` cap held back is never treated as unbanned: being over the cap
delays a ban, it does not remove one.

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the
BunkerWeb documentation first.

## SysWarden side

SysWarden documents its own side of this integration in
[its wiki](https://github.com/duggytuxy/syswarden/wiki/BunkerWeb-Integration); read it
alongside this page, since it is the authority on what the peer accepts.

Enable the HA API on the SysWarden host and allow the BunkerWeb **scheduler** container's
IP (that is where the jobs run):

```toml
[integrations.ha]
enabled   = true
peer_ips  = ["<IP of bw-scheduler>"]
peer_port = 62026
token     = "<a long random token>"

[integrations.bunkerweb]
enabled = true
```

> [!IMPORTANT]
> Set a token. Recent SysWarden versions refuse to start the HA API without one; older
> ones start anyway and skip the bearer check entirely ("Legacy Mode"), leaving the API
> authenticated by source IP alone. Neither is a posture to build on, and the plugin
> refuses to run without `SYSWARDEN_API_TOKEN` for the same reason.

> [!NOTE]
> `[integrations.bunkerweb]` is what unlocks expiring bans and provenance: it is what puts
> `sync_provenance` in the `capabilities` the peer advertises on `GET /ha/status`. Without
> it the plugin falls back to permanent bans tracked in its own registry, and everything
> else keeps working. SysWarden versions that predate the section behave the same way.

> [!NOTE]
> Recent SysWarden versions accept a CIDR in `peer_ips`, so a scheduler on a Docker
> network can be allowed as a subnet. Older ones match the address as an exact string —
> pin the scheduler to a fixed address in your compose file, since a recreated container
> that picks a new IP gets 403s.

## TLS

SysWarden serves the HA API with a self-signed certificate generated per host
(`/var/lib/syswarden/ha/server.crt`). Pick one of three postures, in order of preference:

1. `SYSWARDEN_CA_BUNDLE` — mount a CA bundle that signs the peer's certificate.
2. `SYSWARDEN_SSL_FINGERPRINT` — pin the certificate's SHA-256 fingerprint, which is the
   practical option for a self-signed peer. Read it on the SysWarden host with:

   ```bash
   openssl x509 -in /var/lib/syswarden/ha/server.crt -noout -fingerprint -sha256
   ```

3. `SYSWARDEN_SSL_INSECURE=yes` — accept any certificate. The bearer token travels on that
   connection, so an active MITM captures it.

With none of the three set, the jobs **refuse to start** rather than downgrade silently.

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb
documentation for the installation procedure depending on your integration (the short
version: drop the `syswarden/` directory into the scheduler's `/data/plugins/` and restart).

## Docker

Set the SysWarden settings on the **scheduler** service — that is where the plugin's jobs
run and where BunkerWeb reads its configuration.

```yaml
services:
  bunkerweb:
    image: bunkerity/bunkerweb:1.6.11
    ...
    networks:
      - bw-services

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.11
    ...
    environment:
      SERVER_NAME: "app.example.com"
      USE_REVERSE_PROXY: "yes"
      REVERSE_PROXY_HOST: "http://app:3000"
      REVERSE_PROXY_URL: "/"

      USE_SYSWARDEN: "yes" # Mandatory
      SYSWARDEN_PEERS: "192.168.1.10" # host or host:port, default port 62026
      SYSWARDEN_API_TOKEN: "<the token from [integrations.ha]>"
      SYSWARDEN_SSL_FINGERPRINT: "AB:CD:...:EF" # openssl output is accepted as is

      # Push BunkerWeb bans down to nftables
      USE_SYSWARDEN_BAN_PUSH: "yes"
      SYSWARDEN_ENFORCEMENT: "audit" # start here, switch to "enforcing" once the logs look right

      # Deny SysWarden's blocklist at Layer 7 too (per service)
      USE_SYSWARDEN_BLOCKLIST: "yes"
      USE_SYSWARDEN_WHITELIST: "yes"

    networks:
      - bw-universe
      - bw-services
```

> [!TIP]
> Start with `SYSWARDEN_ENFORCEMENT: "audit"`. Every add and remove the job _would_ make is
> logged, and nothing is sent. Read one or two passes in the scheduler logs, then switch to
> `enforcing`.

## Linux

Same settings, in `/etc/bunkerweb/variables.env`, then `systemctl restart bunkerweb-scheduler`.

On a Linux integration BunkerWeb and SysWarden usually share the host, so `SYSWARDEN_PEERS`
is typically `127.0.0.1` and `peer_ips` contains `127.0.0.1`.

# Secrets

`SYSWARDEN_API_TOKEN` supports the Docker-secret `<NAME>_FILE` convention: set
`SYSWARDEN_API_TOKEN_FILE=/run/secrets/syswarden_api_token` and the jobs read the token
from that file instead of the environment.

# Settings

| Setting                           | Default     | Context   | Multiple | Description                                                                                                                                                                                                                |
| --------------------------------- | ----------- | --------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `USE_SYSWARDEN`                   | `no`        | global    | no       | Activate the SysWarden integration (ban push, blocklist download, telemetry).                                                                                                                                              |
| `SYSWARDEN_PEERS`                 |             | global    | no       | SysWarden HA API endpoints, space-separated, as host or host:port (default port 62026). Bracket an IPv6 literal to give it a port: [2001:db8::1]:62026.                                                                    |
| `SYSWARDEN_API_TOKEN`             |             | global    | no       | Bearer token of the SysWarden HA API ([integrations.ha] token). Required: a peer with an empty token authenticates on the peer IP alone. Supports the SYSWARDEN_API_TOKEN_FILE Docker-secret convention.                   |
| `SYSWARDEN_CA_BUNDLE`             |             | global    | no       | Path to a mounted CA bundle used to verify the peer's certificate, for example /etc/syswarden/ha-ca.pem.                                                                                                                   |
| `SYSWARDEN_SSL_FINGERPRINT`       |             | global    | no       | SHA-256 fingerprint of the peer's certificate to pin, when no CA bundle is available (SysWarden self-signs per host). Read it with: openssl x509 -in /var/lib/syswarden/ha/server.crt -noout -fingerprint -sha256          |
| `SYSWARDEN_SSL_INSECURE`          | `no`        | global    | no       | Talk to the peer without verifying its certificate. Explicit opt-out: without a CA bundle or a fingerprint, the jobs refuse to run instead of degrading silently.                                                          |
| `SYSWARDEN_TIMEOUT`               | `10`        | global    | no       | Connect and read timeout in seconds for SysWarden HA API requests.                                                                                                                                                         |
| `USE_SYSWARDEN_BAN_PUSH`          | `no`        | global    | no       | Push BunkerWeb's active bans to the SysWarden blocklist, so the attacker is dropped in the kernel for every service on the host, containers included.                                                                      |
| `SYSWARDEN_ENFORCEMENT`           | `enforcing` | global    | no       | 'enforcing' pushes and removes bans; 'audit' logs every add and remove it would have made without sending anything. Start in audit.                                                                                        |
| `SYSWARDEN_BAN_MAX_ITEMS`         | `10000`     | global    | no       | Maximum number of bans pushed per pass, 0 meaning no limit. Beyond it the set is truncated deterministically (sorted) and the count dropped is logged; a ban held back this way is delayed, never removed from the peer.   |
| `SYSWARDEN_BAN_CHUNK_SIZE`        | `500`       | global    | no       | Number of entries per POST/DELETE request to /ha/sync. A peer refuses an oversized batch outright (500 entries with ban provenance, 1024 without), so a higher value is lowered to whichever ceiling applies to that peer. |
| `SYSWARDEN_BAN_SCOPE_FILTER`      |             | global    | no       | Space-separated list of services whose bans are propagated. Empty means every service. Global bans are always propagated: they are not tied to a service.                                                                  |
| `SYSWARDEN_BAN_MIN_TTL`           | `0`         | global    | no       | Skip bans with less than N seconds left, so rate-limit noise does not churn the nftables set. Permanent bans are never skipped.                                                                                            |
| `SYSWARDEN_BAN_SOURCE`            | `bunkerweb` | global    | no       | Provenance tag written on every pushed ban. A peer that tracks provenance only lets us delete what carries our own tag, so give each BunkerWeb cluster pushing to the same host a distinct value.                          |
| `USE_SYSWARDEN_BLOCKLIST`         | `no`        | multisite | no       | Download SysWarden's blocklist and deny those IPs at Layer 7 as well. Useful when BunkerWeb and SysWarden do not run on the same host.                                                                                     |
| `USE_SYSWARDEN_WHITELIST`         | `no`        | multisite | no       | Download SysWarden's whitelist and let it win over the blocklist, so an operator's explicit allow keeps working at Layer 7 too.                                                                                            |
| `SYSWARDEN_BLOCKLIST_INTERVAL`    | `hour`      | global    | no       | How often the blocklist and whitelist are downloaded.                                                                                                                                                                      |
| `SYSWARDEN_BLOCKLIST_EXCLUDE_OWN` | `yes`       | global    | no       | Subtract the IPs this plugin pushed from the downloaded blocklist: BunkerWeb already bans them at Layer 7, denying them twice adds nothing.                                                                                |

# Troubleshooting

- **A job exits 2 with "No usable TLS setting".** That is the gate doing its job: set
  `SYSWARDEN_CA_BUNDLE`, or `SYSWARDEN_SSL_FINGERPRINT`, or accept the risk with
  `SYSWARDEN_SSL_INSECURE=yes`.
- **The peer answers 403.** Either the scheduler's source IP is outside `peer_ips` — check
  the address the container actually uses, and pin it in your compose file — or
  `[integrations.bunkerweb] enabled` is off, which only refuses expiring bans and
  provenance while the rest keeps working.
- **`syswarden-ban-push` finds 0 bans.** Without `USE_REDIS=yes` the bans are read from
  each instance's shared dict through `GET /bans`, which a BunkerWeb restart empties.
  That is expected: the ban was lost on the BunkerWeb side too, and the next pass removes
  it from SysWarden as well.
- **Nothing is ever pushed.** Check `SYSWARDEN_ENFORCEMENT` — in `audit` the job logs what
  it would do and sends nothing, which is exactly what the mode is for.
- **An operator entry disappeared from SysWarden's blocklist.** Against a peer that tracks
  provenance this cannot happen: an operator entry carries a different source and is out of
  the plugin's reach. Against an older peer the plugin deletes what its own `pushed.json`
  registry lists, so an address it pushed first and an operator added afterwards is in the
  registry and goes away once BunkerWeb stops banning it. Whitelist it on the SysWarden
  side instead.
- **`USE_SYSWARDEN_BLOCKLIST=yes` denies nobody.** The Lua side fails open until
  `blocklist.list` exists. Confirm `syswarden-blocklist-download` ran (the plugin's ping,
  `POST /syswarden/ping`, reports peer reachability from the cached telemetry).

# Notes

- **Fail-open by design.** The Layer 7 deny path never denies while the lists are empty or
  the IP matcher errors out. A dead peer or a job that has not run yet cannot lock everyone
  out of your sites.
- **The kernel drop is the fast path, not the only one.** A pushed ban reaches nftables
  within a minute (`syswarden-ban-push`); until then, and for anything SysWarden cannot see,
  BunkerWeb's own ban is what enforces the block.
- **Bans are flattened.** BunkerWeb bans can be scoped to one service; an nftables set is
  host-wide. Use `SYSWARDEN_BAN_SCOPE_FILTER` to choose which services' bans are allowed to
  become host-wide drops.
- **A lifetime is sent once, not renewed.** On a peer that tracks provenance the lifetime
  goes out with the push and is never extended, so a BunkerWeb ban that is later made longer
  still expires on the peer at its original time. The next pass sees it gone and pushes it
  again, which costs at most a minute of kernel-level coverage.
- **Stream support is partial.** In the stream (`preread`) context only the blocklist and
  whitelist check runs.
- **Free bonus, no code involved.** SysWarden's WAAP discovers `/var/log/nginx/access.log`
  on its own when `waap.bruteforce_logs` is left at `auto`. Mounting BunkerWeb's
  `/var/log/nginx` onto the host gives it your full BunkerWeb traffic without this plugin
  being involved at all.
- **Two HA API generations, detected per peer.** The plugin reads each peer's advertised
  `capabilities` on every pass and speaks whichever wire format that peer understands, so a
  cluster can be upgraded one host at a time. The HA API is still young; if a route or
  payload changes upstream, the jobs log the failure per peer and keep the cached lists.
