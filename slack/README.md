# Slack plugin

```mermaid
flowchart TD
    accTitle: BunkerWeb Slack plugin notification flow
    accDescr: The plugin does not block traffic. When BunkerWeb denies a request, slack.lua runs on the log phase, builds a plain-text message, and schedules an async ngx.timer so the HTTP POST to the Slack webhook happens after the response, leaving request latency unaffected. A 429 rate-limit response is retried after its Retry-After delay.

    client([Client / Browser])

    subgraph bw[BunkerWeb]
        direction TB
        decision{"Request denied?"}
        log["slack.lua (log phase):<br/>build text message<br/>(IP, reason, request, headers)"]
        timer["ngx.timer.at(0):<br/>async, after response"]
        decision -->|yes| log --> timer
    end

    slack[["Slack webhook<br/>SLACK_WEBHOOK_URL"]]
    served([Response already returned to client])

    client -->|request| decision
    decision -->|no| served
    timer -.->|"HTTP POST text (async)"| slack
    slack -.->|"429 -> retry after Retry-After"| timer

    classDef ok fill:#eafaf0,stroke:#27ae60,color:#14532d;
    classDef deny fill:#fdecea,stroke:#e74c3c,color:#7f1d1d;
    classDef svc fill:#e8f4fd,stroke:#2980b9,color:#0c4a6e;
    classDef app fill:#ffffff,stroke:#334155,color:#0f172a;
    class served ok;
    class log,timer deny;
    class slack svc;
    class client,decision app;
```

This [BunkerWeb](https://www.bunkerweb.io/?utm_campaign=self&utm_source=github) plugin will automatically send you attack notifications on a Slack channel of your choice using a webhook.

# Table of contents

- [Slack plugin](#slack-plugin)
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

You will need to setup a Slack webhook URL, you will find more information [here](https://api.slack.com/messaging/webhooks).

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
      - USE_SLACK=yes
      - SLACK_WEBHOOK_URL=https://api.slack.com/messaging/webhooks/...
    ...
```

## Swarm

```yaml
services:

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0-rc1
    ...
    environment:
      - USE_SLACK=yes
      - SLACK_WEBHOOK_URL=https://api.slack.com/messaging/webhooks/...
    ...
```

## Kubernetes

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/USE_SLACK: "yes"
    bunkerweb.io/SLACK_WEBHOOK_URL: "https://api.slack.com/messaging/webhooks/..."
```

# Settings

| Setting                  | Default                                | Context   | Multiple | Description                                                                                  |
| ------------------------ | -------------------------------------- | --------- | -------- | -------------------------------------------------------------------------------------------- |
| `USE_SLACK`              | `no`                                   | multisite | no       | Enable sending alerts to a Slack channel.                                                    |
| `SLACK_WEBHOOK_URL`      | `https://hooks.slack.com/services/...` | global    | no       | Address of the Slack Webhook.                                                                |
|                          |
| `SLACK_RETRY_IF_LIMITED` | `no`                                   | global    | no       | Retry to send the request if Slack API is rate limiting us (may consume a lot of resources). |

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
