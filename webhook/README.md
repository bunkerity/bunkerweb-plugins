# WebHook plugin

![BunkerWeb plugins version](https://img.shields.io/badge/bunkerweb_plugins-1.11-blue)

```mermaid
flowchart TD
    accTitle: BunkerWeb WebHook plugin notification flow
    accDescr: The plugin does not block traffic. When BunkerWeb denies a request, webhook.lua runs on the log phase, builds a JSON payload, and schedules an async ngx.timer so the HTTP POST to the custom endpoint happens after the response, leaving request latency unaffected. A 429 rate-limit response is retried after its Retry-After delay.

    client([Client / Browser])

    subgraph bw[BunkerWeb]
        direction TB
        decision{"Request denied?"}
        log["webhook.lua (log phase):<br/>build JSON payload<br/>(content: IP, reason, request, headers)"]
        timer["ngx.timer.at(0):<br/>async, after response"]
        decision -->|yes| log --> timer
    end

    endpoint[["Custom HTTP endpoint<br/>WEBHOOK_URL"]]
    served([Response already returned to client])

    client -->|request| decision
    decision -->|no| served
    timer -.->|"HTTP POST JSON (async)"| endpoint
    endpoint -.->|"429 -> retry after Retry-After"| timer

    classDef ok fill:#eafaf0,stroke:#27ae60,color:#14532d;
    classDef deny fill:#fdecea,stroke:#e74c3c,color:#7f1d1d;
    classDef svc fill:#e8f4fd,stroke:#2980b9,color:#0c4a6e;
    classDef app fill:#ffffff,stroke:#334155,color:#0f172a;
    class served ok;
    class log,timer deny;
    class endpoint svc;
    class client,decision app;
```

This [BunkerWeb](https://www.bunkerweb.io/?utm_campaign=self&utm_source=github)
plugin posts an attack notification to a custom HTTP endpoint of your choice
(a webhook) every time BunkerWeb denies a request. It is a generic notifier: it
never inspects or blocks traffic itself - it only reports decisions that
BunkerWeb's other plugins (rate limit, bad behavior, antibot, blacklist, ...)
have already made.

The notification is assembled and dispatched from BunkerWeb's `log` phase, after
the response has already been returned to the client. The actual HTTP `POST`
runs inside an `ngx.timer.at(0, ...)` callback, so it is sent asynchronously and
adds zero latency to the request. The plugin works on both HTTP and stream (L4)
servers.

# Table of contents

- [WebHook plugin](#webhook-plugin)
- [Table of contents](#table-of-contents)
- [How it works](#how-it-works)
- [Setup](#setup)
  - [Docker](#docker)
  - [Swarm](#swarm)
  - [Kubernetes](#kubernetes)
- [Settings](#settings)
- [Payload format](#payload-format)
- [Troubleshooting](#troubleshooting)
- [Notes](#notes)

# How it works

For each request that reaches a site with `USE_WEBHOOK=yes`:

1. BunkerWeb's normal access-phase checks run (rate limit, bad behavior,
   antibot, DNSBL, blacklist, ...). The webhook plugin takes no part in this
   decision and never blocks anything.
2. On the `log` phase, `webhook.lua` runs. If the request was **not** denied
   (`utils.get_reason` returns nothing), the plugin does nothing - only denied
   requests trigger a notification. A companion `log_default` hook covers
   denials that hit the default server when `DISABLE_DEFAULT_SERVER=yes`.
3. For a denied request, the plugin builds a JSON payload of the form
   `{"content": "<message>"}`. The message is a markdown code block holding the
   client IP, the deny reason and its reason data, the raw request line
   (`ngx.var.request`), and every request header. Headers that carry
   credentials are redacted (see [Notes](#notes)).
4. The send is scheduled with `ngx.timer.at(0, self.send, ...)`. The HTTP `POST`
   to `WEBHOOK_URL` (`Content-Type: application/json`) therefore happens
   asynchronously, after the response has been returned - request latency is
   unaffected.
5. If the endpoint replies `429` and `WEBHOOK_RETRY_IF_LIMITED=yes`, the timer
   is rescheduled after the response's `Retry-After` delay. Otherwise any
   non-`2xx` response (including a `429` when retries are disabled) is logged
   and the notification is dropped.

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github)
of the BunkerWeb documentation for the generic plugin installation procedure
(the short version: drop the `webhook/` directory into the scheduler's
`/data/plugins/` and restart). There is no additional service to stand up
besides the receiving endpoint itself.

## Docker

```yaml
services:
  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.11
    ...
    environment:
      USE_WEBHOOK: "yes"
      WEBHOOK_URL: "https://api.example.com/bw"
    ...
```

## Swarm

```yaml
services:
  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.11
    ...
    environment:
      USE_WEBHOOK: "yes"
      WEBHOOK_URL: "https://api.example.com/bw"
    ...
```

## Kubernetes

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/USE_WEBHOOK: "yes"
    bunkerweb.io/WEBHOOK_URL: "https://api.example.com/bw"
```

# Settings

| Setting                    | Default                      | Context   | Multiple | Description                                                                                          |
| -------------------------- | ---------------------------- | --------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `USE_WEBHOOK`              | `no`                         | multisite | no       | Enable sending alerts to a custom webhook.                                                           |
| `WEBHOOK_URL`              | `https://api.example.com/bw` | global    | no       | Address of the webhook.                                                                              |
| `WEBHOOK_RETRY_IF_LIMITED` | `no`                         | global    | no       | Retry to send the request if the remote server is rate limiting us (may consume a lot of resources). |

# Payload format

This is a **generic** webhook, so your endpoint must accept a `POST` whose body
is a single JSON object of the form:

````json
{
  "content": "```Denied request for IP 1.2.3.4 (reason = ... / reason data = {...}).\n\nRequest data :\n\nGET / HTTP/1.1\nhost: app.example.com\nuser-agent: ...\n```"
}
````

The `content` field is a single string carrying a markdown code block. The
plain message inside it is what the notifier-style plugins (Discord, Slack, ...)
also send, so the same receiver shape works across all of them. Parse the
`content` string on your side if you need the structured fields - the plugin
does not send them as separate JSON keys.

The same shape is used by the connectivity test endpoint: a `POST` to
`/webhook/ping` sends `{"content": "```Test message from bunkerweb```"}` to
`WEBHOOK_URL` and reports the result. The BunkerWeb web UI surfaces this as the
plugin's status.

# Troubleshooting

- **No notifications arrive.** Confirm `USE_WEBHOOK=yes` is set on the site and
  that `WEBHOOK_URL` is reachable from the scheduler/BunkerWeb container. Remember
  that **only denied requests** are reported - a site with no blocked traffic
  produces no notifications.
- **Endpoint rejects the payload.** The receiver must accept a `POST` of
  `{"content": "..."}` JSON with `Content-Type: application/json`. A receiver
  expecting a different schema will reject it; adapt the receiver (or front it
  with a small adapter) to the shape in [Payload format](#payload-format).
- **Notifications are silently lost.** Any non-`2xx` response from the endpoint
  is logged as an error in the scheduler/nginx logs and the notification is
  dropped. These failures are **log-only** and never affect the client request.
- **You are being rate-limited.** If the endpoint returns `429`, set
  `WEBHOOK_RETRY_IF_LIMITED=yes` so the plugin honors the `Retry-After` header
  and retries instead of dropping the message (this can consume more resources
  under sustained attacks).
- **Test the connection.** Issue a `POST` to `/webhook/ping` (or use the status
  card in the BunkerWeb web UI) to verify the endpoint receives a test message.

# Notes

- **Denials only, never blocks.** This plugin only reacts to requests that
  BunkerWeb has already denied; it never inspects request content and never
  blocks or delays traffic on its own. Disabling it changes nothing about
  whether a request is allowed.
- **Zero added latency.** The notification is sent from an `ngx.timer.at(0)`
  callback after the response is returned, so the client never waits on the
  webhook round-trip.
- **Failures are log-only.** If the HTTP client cannot be created, the request
  fails, or the endpoint returns a non-`2xx` status, the error is written to the
  logs and the notification is discarded - it is never retried unless it was a
  `429` with `WEBHOOK_RETRY_IF_LIMITED=yes`.
- **Sensitive headers are redacted.** Before headers are placed in the payload,
  values of credential-bearing headers are replaced with `[REDACTED]`:
  `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`,
  `X-Csrf-Token`, `X-Xsrf-Token`, `X-Auth-Token`, `X-Access-Token`,
  `X-Session-Token`, and `X-Amz-Security-Token` (matched case-insensitively).
- **Generic payload shape.** Because the body is just `{"content": "..."}`,
  document this shape for whoever owns the receiving endpoint so they can parse
  the message reliably.
- **Stream support.** The plugin works on stream (L4) servers as well as HTTP
  servers.
