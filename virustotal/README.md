# VirusTotal plugin

<p align="center">
	<img alt="BunkerWeb VirusTotal diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/virustotal/docs/diagram.svg" />
</p>

This [BunkerWeb](https://www.bunkerweb.io) plugin will automatically check if any uploaded file is already analyzed on VirusTotal and deny the request if the file is detected by some antivirus engine(s).

At the moment, submission of new file is not supported, it only checks if files already exist in VT and get the scan result if that's the case.

# Table of contents

- [VirusTotal plugin](#virustotal-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  * [Docker](#docker)
  * [Swarm](#swarm)
  * [Kubernetes](#kubernetes)
- [Settings](#settings)
  * [Plugin](#plugin--bunkerweb-)
  * [bunkerweb-virustotal](#bunkerweb-virustotal--api-)
- [TODO](#todo)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/plugins) of the BunkerWeb documentation first.

You will need a VirusTotal API key to contact their API (see [here](https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key)). The free API key is also working but you should check the terms of service and limits as described [here](https://support.virustotal.com/hc/en-us/articles/115002119845-What-is-the-difference-between-the-public-API-and-the-private-API-).

Please note that an additionnal service named **bunkerweb-virustotal** is required : it's a simple REST API that will handle the checks to the VirusTotal API. A redis service is also recommended to cache VirusTotal API results in case high performance is needed (it will also save you some requests made to the VT API by the way).

# Setup

See the [plugins section](https://docs.bunkerweb.io/plugins) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker

```yaml
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.4.1
    ...
    environment:
      - USE_VIRUSTOTAL=yes
      - VIRUSTOTAL_API=http://virustotal-api:8000
    ...

  virustotal-api:
    image: bunkerity/bunkerweb-virustotal
    environment:
      - API_KEY=your-virustotal-api-key
      - REDIS_HOST=redis

  redis:
    image: redis:7-alpine
```

## Swarm

```yaml
version: '3.5'

services:

  mybunker:
    image: bunkerity/bunkerweb:1.4.1
    ...
    environment:
      - USE_VIRUSTOTAL=yes
      - VIRUSTOTAL_API=http://virustotal-api:8000
    ...
    networks:
      - bw-plugins
    ...

  virustotal-api:
    image: bunkerity/bunkerweb-virustotal
    environment:
      - API_KEY=your-virustotal-api-key
      - REDIS_HOST=redis
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
  name: bunkerweb-virustotal
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bunkerweb-virustotal
  template:
    metadata:
      labels:
        app: bunkerweb-virustotal
    spec:
      containers:
      - name: bunkerweb-virustotal
        image: bunkerity/bunkerweb-virustotal
        env:
        - name: API_KEY
          value: "your-virustotal-api-key"
        - name: REDIS_HOST
          value: "redis"
---
apiVersion: v1
kind: Service
metadata:
  name: svc-bunkerweb-virustotal
spec:
  selector:
    app: bunkerweb-virustotal
  ports:
    - protocol: TCP
      port: 8000
      targetPort: 8000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bunkerweb-virustotal-redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bunkerweb-virustotal-redis
  template:
    metadata:
      labels:
        app: bunkerweb-virustotal-redis
    spec:
      containers:
      - name: bunkerweb-virustotal-redis
        image: redis:7-alpine
---
apiVersion: v1
kind: Service
metadata:
  name: svc-bunkerweb-virustotal-redis
spec:
  selector:
    app: bunkerweb-virustotal-redis
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
    bunkerweb.io/USE_VIRUSTOTAL: "yes"
    bunkerweb.io/VIRUSTOTAL_API: "http://virustotal-api:8000"
...
```

# Settings

## Plugin (BunkerWeb)

| Setting          | Default                      | Description                                                                               |
| :--------------: | :--------------------------: | :---------------------------------------------------------------------------------------- |
| `USE_VIRUSTOTAL` | `no`                         | When set to `yes`, uploaded files will be checked with the VirusTotal plugin.             |
| `VIRUSTOTAL_API` | `http://virustotal-api:8000` | Address of the VirusTotal "helper" that will check the files and talk to the real VT API. |

## bunkerweb-virustotal (API)

| Setting            | Default                      | Description                                            |
| :----------------: | :-----: | :-------------------------------------------------------------------------- |
| `API_KEY`          |         | API key for the VirusTotal API.                                             |
| `MALICIOUS_COUNT`  | `3`     | Minimum number of "malicious" detections to consider the file as infected.  |
| `SUSPICIOUS_COUNT` | `5`     | Minimum number of "suspicious" detections to consider the file as infected. |
| `REDIS_HOST`       |         | Optional Redis hostname/IP to cache results from VT API.                    |
| `REDIS_PORT`       | `6379`  | Port of the Redis service.                                                  |
| `REDIS_DB`         | `0`     | Redis database number to use.                                               |

# TODO

* Upload files to VT
* Test and document clustered mode
* Additional security checks like IP