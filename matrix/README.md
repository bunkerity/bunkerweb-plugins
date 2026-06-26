# Matrix Notification Plugin

```mermaid
flowchart TD
    accTitle: BunkerWeb Matrix plugin notification flow
    accDescr: The plugin does not block traffic. When BunkerWeb denies a request, matrix.lua runs on the log phase, builds an HTML and plain-text message with a unique transaction id, and schedules an async ngx.timer so the HTTP PUT to the Matrix room happens after the response, leaving request latency unaffected. The transaction id makes the send idempotent across retries.

    client([Client / Browser])

    subgraph bw[BunkerWeb]
        direction TB
        decision{"Request denied?"}
        log["matrix.lua (log phase):<br/>build HTML + plain body,<br/>unique txn_id"]
        timer["ngx.timer.at(0):<br/>async, after response"]
        decision -->|yes| log --> timer
    end

    matrix[["Matrix homeserver:<br/>PUT /_matrix/client/r0/rooms/<br/>{room}/send/m.room.message/{txn_id}<br/>(Bearer token)"]]
    served([Response already returned to client])

    client -->|request| decision
    decision -->|no| served
    timer -.->|"HTTP PUT (async)"| matrix

    classDef ok fill:#eafaf0,stroke:#27ae60,color:#14532d;
    classDef deny fill:#fdecea,stroke:#e74c3c,color:#7f1d1d;
    classDef svc fill:#e8f4fd,stroke:#2980b9,color:#0c4a6e;
    classDef app fill:#ffffff,stroke:#334155,color:#0f172a;
    class served ok;
    class log,timer deny;
    class matrix svc;
    class client,decision app;
```

This [BunkerWeb](https://www.bunkerweb.io/?utm_campaign=self&utm_source=github) plugin will automatically send attack notifications to a Matrix room of your choice.

# Table of contents

- [Matrix Notification Plugin](#matrix-notification-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Docker](#docker)
  - [Swarm](#swarm)
  - [Kubernetes](#kubernetes)
- [Settings](#settings)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation first.

You will need:

- A Matrix server URL (e.g., `https://matrix.org`).
- A valid access token for the Matrix user you want to send notifications from.
- A room ID where notifications will be sent to. The matrix user has to be Member of that room.

Please refer to your homeserver's docs if you need help setting these up.

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation for the installation procedure depending on your integration.

There is no additional service setup required beyond configuring the plugin itself.

## Docker

```yaml
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.5.9
    ...
    environment:
      - USE_MATRIX=yes
      - MATRIX_BASE_URL=https://matrix.org
      - MATRIX_ROOM_ID=!yourRoomID:matrix.org
      - MATRIX_ACCESS_TOKEN=your-access-token
    ...
```

## Swarm

```yaml
version: '3'

services:

  mybunker:
    image: bunkerity/bunkerweb:1.5.9
    ..
    environment:
      - USE_MATRIX=yes
      - MATRIX_BASE_URL=https://matrix.org
      - MATRIX_ROOM_ID=!yourRoomID:matrix.org
      - MATRIX_ACCESS_TOKEN=your-access-token
    ...
```

## Kubernetes

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/USE_MATRIX: "yes"
    bunkerweb.io/MATRIX_BASE_URL: "https://matrix.org"
    bunkerweb.io/MATRIX_ROOM_ID: "!yourRoomID:matrix.org"
    bunkerweb.io/MATRIX_ACCESS_TOKEN: "your-access-token"
```

# Settings

| Setting                  | Default                  | Context   | Multiple | Description                                               |
| ------------------------ | ------------------------ | --------- | -------- | --------------------------------------------------------- |
| `USE_MATRIX`             | `no`                     | multisite | no       | Enable sending alerts to a Matrix room.                   |
| `MATRIX_BASE_URL`        | `https://matrix.org`     | global    | no       | Base URL of the Matrix server (e.g., https://matrix.org). |
| `MATRIX_ROOM_ID`         | `!yourRoomID:matrix.org` | global    | no       | Room ID of the Matrix room to send notifications to.      |
| `MATRIX_ACCESS_TOKEN`    |                          | global    | no       | Access token to authenticate with the Matrix server.      |
| `MATRIX_ANONYMIZE_IP`    | `no`                     | global    | no       | Mask the IP address in notifications.                     |
| `MATRIX_INCLUDE_HEADERS` | `no`                     | global    | no       | Include request headers in notifications.                 |
