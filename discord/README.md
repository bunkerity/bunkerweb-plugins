# Discord plugin

<p align="center">
	<img alt="BunkerWeb Discord diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/discord/docs/diagram.svg" />
</p>

This [BunkerWeb](https://www.bunkerweb.io) plugin will automatically send you attack notifications on a Discord channel of your choice using a webhook.

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

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation first.

You will need to setup a Discord webhook URL, you will find more information [here](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation for the installation procedure depending on your integration.

There is no additional services to setup besides the plugin itself.

## Docker

```yaml
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.5.1
    ...
    environment:
      - USE_DISCORD=yes
      - DISCORD_WEBHOOK_URL=https://discordapp.com/api/webhooks/...
    ...
```

## Swarm

```yaml
version: '3.5'

services:

  mybunker:
    image: bunkerity/bunkerweb:1.5.1
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
