# WebHook plugin

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

This [BunkerWeb](https://www.bunkerweb.io/?utm_campaign=self&utm_source=github) plugin will automatically send you attack notifications on a custom HTTP endpoint of your choice using a webhook.

# Table of contents

- [WebHook plugin](#webhook-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Docker](#docker)
  - [Swarm](#swarm)
  - [Kubernetes](#kubernetes)
- [Settings](#settings)
- [TODO](#todo)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation first.

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation for the installation procedure depending on your integration.

There is no additional services to setup besides the plugin itself.

## Docker

```yaml
services:

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0-rc1
    ...
    environment:
      - USE_WEBHOOK=yes
      - WEBHOOK_URL=https://api.example.com/bw
    ...
```

## Swarm

```yaml
services:

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0-rc1
    ..
    environment:
      - USE_WEBHOOK=yes
      - WEBHOOK_URL=https://api.example.com/bw
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

# TODO

- Add more info in notification :
  - Date
  - Country of IP
  - ASN of IP
  - ...
- Add settings to control what details to send :
  - Anonymize IP
  - Add body
  - Add headers
