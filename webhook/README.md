# WebHook plugin

<p align="center">
	<img alt="BunkerWeb WebHook diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/webhook/docs/diagram.svg" />
</p>

This [BunkerWeb](https://www.bunkerweb.io) plugin will automatically send you attack notifications on a custom HTTP endpoint of your choice using a webhook.

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

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation first.

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
      - USE_WEBHOOK=yes
      - WEBHOOK_URL=https://api.example.com/bw
    ...
```

## Swarm

```yaml
version: '3'

services:

  mybunker:
    image: bunkerity/bunkerweb:1.5.1
    ...
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
...
```

# Settings

| Setting | Default | Description |
| :-----: | :-----: | :---------- |
| `USE_WEBHOOK` | `no` | When set to `yes`, notifications of denied requests will be sent to a custom HTTP endpoint using webhook. |
| `WEBHOOK_URL` | `https://discordapp.com/api/webhooks/...` | Address of the HTTP endpoint where webhooks will be sent to. |
| `WEBHOOK_RETRY_IF_LIMITED` | `no` | When this settings is set to `yes`, the plugin will retry to send the notification later in case we are rate limited. It may consumes some resources if you are under heavy attacks by the way. |

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