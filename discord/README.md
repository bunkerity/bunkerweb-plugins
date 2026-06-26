# Discord plugin

```mermaid
flowchart TD
    accTitle: BunkerWeb Discord plugin notification flow
    accDescr: The plugin does not block traffic. When BunkerWeb denies a request, discord.lua runs on the log phase, builds a JSON embed, and schedules an async ngx.timer so the HTTP POST to the Discord webhook happens after the response, leaving request latency unaffected. A 429 rate-limit response is retried after its Retry-After delay.

    client([Client / Browser])

    subgraph bw[BunkerWeb]
        direction TB
        decision{"Request denied?"}
        log["discord.lua (log phase):<br/>build JSON embed<br/>(request, reason, headers)"]
        timer["ngx.timer.at(0):<br/>async, after response"]
        decision -->|yes| log --> timer
    end

    discord[["Discord webhook<br/>DISCORD_WEBHOOK_URL"]]
    served([Response already returned to client])

    client -->|request| decision
    decision -->|no| served
    timer -.->|"HTTP POST (async)"| discord
    discord -.->|"429 -> retry after Retry-After"| timer

    classDef ok fill:#eafaf0,stroke:#27ae60,color:#14532d;
    classDef deny fill:#fdecea,stroke:#e74c3c,color:#7f1d1d;
    classDef svc fill:#e8f4fd,stroke:#2980b9,color:#0c4a6e;
    classDef app fill:#ffffff,stroke:#334155,color:#0f172a;
    class served ok;
    class log,timer deny;
    class discord svc;
    class client,decision app;
```

This [BunkerWeb](https://www.bunkerweb.io/?utm_campaign=self&utm_source=github) plugin will automatically send you attack notifications on a Discord channel of your choice using a webhook.

# Table of contents

- [Discord plugin](#discord-plugin)
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

You will need to setup a Discord webhook URL, you will find more information [here](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).

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
      - USE_DISCORD=yes
      - DISCORD_WEBHOOK_URL=https://discordapp.com/api/webhooks/...
    ...
```

## Swarm

```yaml
services:

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0-rc1
    ...
    environment:
      - USE_DISCORD=yes
      - DISCORD_WEBHOOK_URL=https://discordapp.com/api/webhooks/...
    ...
    networks:
      - bw-plugins
    ...

networks:
  bw-plugins:
    driver: overlay
    attachable: true
    name: bw-plugins
...
```

## Kubernetes

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/USE_DISCORD: "yes"
    bunkerweb.io/DISCORD_WEBHOOK_URL: "https://discordapp.com/api/webhooks/..."
```

# Settings

| Setting                    | Default                                   | Context   | Multiple | Description                                                                                    |
| -------------------------- | ----------------------------------------- | --------- | -------- | ---------------------------------------------------------------------------------------------- |
| `USE_DISCORD`              | `no`                                      | multisite | no       | Enable sending alerts to a Discord channel.                                                    |
| `DISCORD_WEBHOOK_URL`      | `https://discordapp.com/api/webhooks/...` | global    | no       | Address of the Discord Webhook.                                                                |
|                            |
| `DISCORD_RETRY_IF_LIMITED` | `no`                                      | global    | no       | Retry to send the request if Discord API is rate limiting us (may consume a lot of resources). |

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
