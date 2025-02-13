# Matrix Notification Plugin

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
- [TODO](#todo)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation first.

You will need:
- A Matrix server URL (e.g., `https://matrix.org`).
- A valid access token for the Matrix user you want to sent notifications from.
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
    image: bunkerity/bunkerweb:1.5.10
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
    image: bunkerity/bunkerweb:1.5.10
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

| Setting              | Default                      | Context   | Multiple | Description                                                                                         |
| -------------------- | ---------------------------- | --------- | -------- | --------------------------------------------------------------------------------------------------- |
| `USE_MATRIX`         | `no`                         | multisite | no       | Enable sending alerts to a Matrix room.                                                             |
| `MATRIX_BASE_URL`     | `https://matrix.org`          | global    | no       | Base URL of the Matrix server.                                                                      |
| `MATRIX_ROOM_ID`      | `!yourRoomID:matrix.org`      | global    | no       | Room ID of the Matrix room to send notifications to.                                                |
| `MATRIX_ACCESS_TOKEN` | ` `                           | global    | no       | Access token to authenticate with the Matrix server.                                                |
| `MATRIX_ANONYMIZE_IP`        | `no`                         | global | no       | Mask the IP address in notifications.                                                               |
| `MATRIX_INCLUDE_HEADERS`     | `no`                        | global | no       | Include request headers in notifications.                                                           |
