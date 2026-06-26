# ClamAV plugin

```mermaid
flowchart TD
    accTitle: BunkerWeb ClamAV plugin request flow
    accDescr: A multipart upload first passes BunkerWeb core checks, then clamav.lua streams each file part to the clamd daemon over the binary INSTREAM TCP protocol. A SHA-512 cache short-circuits files already scanned. A clean verdict reaches the upstream while a detection denies the request.

    client([Client / Browser])

    subgraph bw[BunkerWeb access phase]
        direction TB
        core["1. Core checks first:<br/>rate limit, bad behavior, antibot,<br/>DNSBL, black / whitelist"]
        lua["2. clamav.lua:<br/>parse multipart parts that have a filename<br/>(resty.upload streaming)"]
        cache{{"SHA-512 cache hit?"}}
        core --> lua --> cache
    end

    clamd[["clamd daemon:<br/>INSTREAM scan"]]
    verdict{"Scan verdict"}
    allow["Allow to upstream"]
    deny["Deny request<br/>(get_deny_status)"]
    upstream([Upstream app])

    client -->|"file upload (multipart)"| core
    cache -.->|miss| clamd
    clamd -.->|"chunks framed by a 4-byte<br/>big-endian length, zero-frame end"| verdict
    cache -->|hit| verdict
    verdict -->|clean| allow
    verdict -->|virus found| deny
    allow --> upstream

    classDef ok fill:#eafaf0,stroke:#27ae60,color:#14532d;
    classDef deny fill:#fdecea,stroke:#e74c3c,color:#7f1d1d;
    classDef svc fill:#e8f4fd,stroke:#2980b9,color:#0c4a6e;
    classDef app fill:#ffffff,stroke:#334155,color:#0f172a;
    class allow,upstream ok;
    class deny deny;
    class clamd svc;
    class client,core,lua,cache app;
```

This [BunkerWeb](https://www.bunkerweb.io/?utm_campaign=self&utm_source=github) plugin will automatically check if any uploaded file is detected by the ClamAV antivirus engine and deny the request if that's the case.

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

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation first.

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker

```yaml
services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.6.0-rc1
    ...
    networks:
      - bw-plugins
    ...

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0-rc1
    ...
    environment:
      - USE_CLAMAV=yes
      - CLAMAV_HOST=clamav
    ...

  clamav:
    image: clamav/clamav:1.4
    volumes:
      - ./clamav-data:/var/lib/clamav
    networks:
      - bw-plugins

networks:
  # BunkerWeb networks
  ...
  bw-plugins:
    name: bw-plugins
```

## Swarm

```yaml
services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.6.0-rc1
    ...
    networks:
      - bw-plugins
    ...

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0-rc1
    ...
    environment:
      - USE_CLAMAV=yes
      - CLAMAV_HOST=clamav
    ...

  clamav:
    image: clamav/clamav:1.4
    networks:
      - bw-plugins

networks:
  # BunkerWeb networks
  ...
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
          image: clamav/clamav:1.4
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

| Setting          | Default  | Context   | Multiple | Description                                                                            |
| ---------------- | -------- | --------- | -------- | -------------------------------------------------------------------------------------- |
| `USE_CLAMAV`     | `no`     | multisite | no       | Activate automatic scan of uploaded files with ClamAV.                                 |
| `CLAMAV_HOST`    | `clamav` | global    | no       | ClamAV hostname or IP address.                                                         |
| `CLAMAV_PORT`    | `3310`   | global    | no       | ClamAV port.                                                                           |
| `CLAMAV_TIMEOUT` | `1000`   | global    | no       | Network timeout in milliseconds when communicating with ClamAV (e.g. 1000 = 1 second). |

# TODO

- Test and document clustered mode
- Custom ClamAV configuration
- Document Linux integration
