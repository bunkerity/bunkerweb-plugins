# ClamAV plugin

<p align="center">
	<img alt="BunkerWeb ClamAV diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/clamav/docs/diagram.svg" />
</p>

This [BunkerWeb](https://www.bunkerweb.io) plugin will automatically check if any uploaded file is detected by the ClamAV antivirus engine and deny the request if that's the case.

# Table of contents

- [ClamAV plugin](#clamav-plugin)
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

## Docker

```yaml
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.5.3
    ...
    environment:
      - USE_CLAMAV=yes
      - CLAMAV_HOST=clamav
    networks:
      - bw-plugins
    ...

  clamav:
    image: clamav/clamav:1.2
    volumes:
      - ./clamav-data:/var/lib/clamav
    networks:
      - bw-plugins
```

## Swarm

```yaml
version: '3'

services:

  mybunker:
    image: bunkerity/bunkerweb:1.5.3
    ...
    environment:
      - USE_CLAMAV=yes
      - CLAMAV_HOST=clamav
    ...
    networks:
      - bw-plugins
    ...

  clamav:
    image: clamav/clamav:1.2
    networks:
      - bw-plugins

networks:
  bw-plugins:
    driver: overlay
    attachable: true
    name: bw-plugins
...
```

## Kubernetes

First you will need to deploy the dependencies :

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bunkerweb-clamav
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bunkerweb-clamav
  template:
    metadata:
      labels:
        app: bunkerweb-clamav
    spec:
      containers:
        - name: bunkerweb-clamav
          image: clamav/clamav:1.2
---
apiVersion: v1
kind: Service
metadata:
  name: svc-bunkerweb-clamav
spec:
  selector:
    app: bunkerweb-clamav
  ports:
    - protocol: TCP
      port: 3310
      targetPort: 3310
```

Then you can configure the plugin :

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/USE_CLAMAV: "yes"
    bunkerweb.io/CLAMAV_HOST: "svc-bunkerweb-clamav.default.svc.cluster.local"
```

# Settings

| Setting          | Default  | Context   | Multiple | Description                                             |
| ---------------- | -------- | --------- | -------- | ------------------------------------------------------- |
| `USE_CLAMAV`     | `no`     | multisite | no       | Activate automatic scan of uploaded files with ClamAV.  |
| `CLAMAV_HOST`    | `clamav` | global    | no       | ClamAV hostname or IP address.                          |
| `CLAMAV_PORT`    | `3310`   | global    | no       | ClamAV port.                                            |
| `CLAMAV_TIMEOUT` | `1000`   | global    | no       | Network timeout (in ms) when communicating with ClamAV. |

# TODO

- Test and document clustered mode
- Custom ClamAV configuration
- Document Linux integration
