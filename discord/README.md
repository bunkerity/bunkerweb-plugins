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
- [Settings](#settings)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/plugins) of the BunkerWeb documentation first.

You will need to setup a Discord webhook URL, you will find more information [here](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).

# Setup

See the [plugins section](https://docs.bunkerweb.io/plugins) of the BunkerWeb documentation for the installation procedure depending on your integration.

There is no additional services to setup besides the plugin itself.

## Docker

```yaml
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.4.1
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
    image: bunkerity/bunkerweb:1.4.1
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
...
```

# Settings

| Setting | Default | Description |
| :-----: | :-----: | :---------- |
| `USE_DISCORD` | `no` | When set to `yes`, notifications of denied requests will be sent to a Discord webhook. |
| `DISCORD_WEBHOOK_URL` | `https://discordapp.com/api/webhooks/...` | Address of the Discord webhook where notifications will be sent to. |
| `DISCORD_RETRY_IF_LIMITED` | `no` | Discord is applying a rate-limit ton their API. When this settings is set to `yes`, the plugin will retry to send the notification later. It may consumes some resources if you are under heavy attacks by the way. |

# TODO

* Add more info in notification :
  * Date
  * Country of IP
  * ASN of IP
  * ...
* Add settings to control what details to send :
  * Anonymize IP
  * Add body
  * Add headers