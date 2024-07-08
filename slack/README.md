# Slack plugin

<p align="center">
	<img alt="BunkerWeb Slack diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/slack/docs/diagram.svg" />
</p>

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
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.5.8
    ...
    environment:
      - USE_SLACK=yes
      - SLACK_WEBHOOK_URL=https://api.slack.com/messaging/webhooks/...
    ...
```

## Swarm

```yaml
version: '3.5'

services:

  mybunker:
    image: bunkerity/bunkerweb:1.5.8
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
