# ClamAV plugin

<p align="center">
	<img alt="BunkerWeb ClamAV diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/clamav/docs/diagram.svg" />
</p>

This [BunkerWeb](https://www.bunkerweb.io) plugin will automatically check if any uploaded file is detect by the ClamAV antivirus engine and deny the request if that's the case.

# Table of contents

- [ClamAV plugin](#clamav-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  * [Docker](#docker)
  * [Swarm](#swarm)
  * [Kubernetes](#kubernetes)
- [Settings](#settings)
  * [Plugin (BunkerWeb)](#plugin--bunkerweb-)
  * [bunkerweb-clamav (API)](#bunkerweb-clamav--api-)
- [TODO](#todo)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation first.

Please note that an additionnal service named **bunkerweb-clamav** is required : it's a simple REST API that will handle the checks to the ClamAV instance(s). A redis service is also recommended to cache ClamAV results in case high performance is needed.

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker

```yaml
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.4.2
    ...
    environment:
      - USE_CLAMAV=yes
      - CLAMAV_API=http://clamav-api:8000
    ...

  clamav-api:
    image: bunkerity/bunkerweb-clamav
    environment:
      - CLAMAV_HOST=clamav
      - REDIS_HOST=redis

  clamav:
    image: clamav/clamav:0.104
    volumes:
      - ./clamav-data:/var/lib/clamav

  redis:
    image: redis:7-alpine
```

## Swarm

```yaml
version: '3.5'

services:

  mybunker:
    image: bunkerity/bunkerweb:1.4.2
    ...
    environment:
      - USE_CLAMAV=yes
      - CLAMAV_API=http://clamav-api:8000
    ...
    networks:
      - bw-plugins
    ...

  clamav-api:
    image: bunkerity/bunkerweb-clamav
    environment:
      - CLAMAV_HOST=clamav
      - REDIS_HOST=redis
    networks:
      - bw-plugins

  clamav:
    image: clamav/clamav:0.104
    networks:
      - bw-plugins

  redis:
    image: redis:7-alpine
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
  name: bunkerweb-clamav-api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bunkerweb-clamav-api
  template:
    metadata:
      labels:
        app: bunkerweb-clamav-api
    spec:
      containers:
      - name: bunkerweb-clamav-api
        image: bunkerity/bunkerweb-clamav
        env:
        - name: CLAMAV_HOST
          value: "svc-bunkerweb-clamav.default.svc.cluster.local"
        - name: REDIS_HOST
          value: "svc-bunkerweb-clamav-redis.default.svc.cluster.local"
---
apiVersion: v1
kind: Service
metadata:
  name: svc-bunkerweb-clamav-api
spec:
  selector:
    app: bunkerweb-clamav-api
  ports:
    - protocol: TCP
      port: 8000
      targetPort: 8000
---
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
        image: clamav/clamav:0.104
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
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bunkerweb-clamav-redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bunkerweb-clamav-redis
  template:
    metadata:
      labels:
        app: bunkerweb-clamav-redis
    spec:
      containers:
      - name: bunkerweb-clamav-redis
        image: redis:7-alpine
---
apiVersion: v1
kind: Service
metadata:
  name: svc-bunkerweb-clamav-redis
spec:
  selector:
    app: bunkerweb-clamav-redis
  ports:
    - protocol: TCP
      port: 6379
      targetPort: 6379
```

Then you can configure the plugin :
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/USE_CLAMAV: "yes"
    bunkerweb.io/CLAMAV_API: "http://svc-bunkerweb-clamav-api.default.svc.cluster.local:8000"
...
```

# Settings

## Plugin (BunkerWeb)

| Setting      | Default                  | Description                                                                                    |
| :----------: | :----------------------: | :--------------------------------------------------------------------------------------------- |
| `USE_CLAMAV` | `no`                     | When set to `yes`, uploaded files will be checked with the ClamAV plugin.                      |
| `CLAMAV_API` | `http://clamav-api:8000` | Address of the ClamAV "helper" that will check the files and talk to the real ClamAV instance. |

## bunkerweb-clamav (API)

| Setting          | Default | Description                                          |
| :--------------: | :-----: | :----------------------------------------------------|
| `CLAMAV_HOST`    |         | Hostname of ClamAV instance.                         |
| `CLAMAV_PORT`    | `3310`  | Port of the clamd service on the ClamAV instance.    |
| `CLAMAV_TIMEOUT` | `1.0`   | Timeout when communicating with the ClamAV instance. |
| `REDIS_HOST`     |         | Optional Redis hostname/IP to cache results.         |
| `REDIS_PORT`     | `6379`  | Port of the Redis service.                           |
| `REDIS_DB`       | `0`     | Redis database number to use.                        |

# TODO

* Test and document clustered mode
* Custom ClamAV configuration
