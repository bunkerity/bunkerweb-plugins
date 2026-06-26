# VirusTotal plugin

```mermaid
flowchart TD
    accTitle: BunkerWeb VirusTotal plugin request flow
    accDescr: A client request first passes BunkerWeb core checks, then virustotal.lua optionally checks the client IP and any uploaded file against the VirusTotal API v3. Both paths share a 24-hour cache (IP keyed by address, file keyed by SHA-256). The suspicious and malicious counts are compared to configurable thresholds, and a result over threshold denies the request.

    client([Client / Browser])

    subgraph bw[BunkerWeb access phase]
        direction TB
        core["1. Core checks first:<br/>rate limit, bad behavior, antibot,<br/>DNSBL, black / whitelist"]
        lua["2. virustotal.lua"]
        ipscan["IP scan (opt-in):<br/>GET /api/v3/ip_addresses/{ip}"]
        filescan["File scan (opt-in):<br/>SHA-256, GET /api/v3/files/{hash}"]
        cache{{"24h cache hit?"}}
        core --> lua
        lua --> ipscan --> cache
        lua --> filescan --> cache
    end

    vt[["VirusTotal API v3"]]
    verdict{"evaluate():<br/>suspicious / malicious<br/>over threshold?"}
    allow["Allow to upstream"]
    deny["Deny request<br/>(get_deny_status)"]
    upstream([Upstream app])

    client -->|request| core
    cache -.->|miss| vt
    vt -.->|"last_analysis_stats"| verdict
    cache -->|hit| verdict
    verdict -->|no| allow
    verdict -->|yes| deny
    allow --> upstream

    classDef ok fill:#eafaf0,stroke:#27ae60,color:#14532d;
    classDef deny fill:#fdecea,stroke:#e74c3c,color:#7f1d1d;
    classDef svc fill:#e8f4fd,stroke:#2980b9,color:#0c4a6e;
    classDef app fill:#ffffff,stroke:#334155,color:#0f172a;
    class allow,upstream ok;
    class deny deny;
    class vt svc;
    class client,core,lua,ipscan,filescan,cache app;
```

This [BunkerWeb](https://www.bunkerweb.io/?utm_campaign=self&utm_source=github) plugin will automatically check if any uploaded file is already analyzed on VirusTotal and deny the request if the file is detected by some antivirus engine(s).

At the moment, submission of new file is not supported, it only checks if files already exist in VT and get the scan result if that's the case.

# Table of contents

- [VirusTotal plugin](#virustotal-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Docker](#docker)
  - [Swarm](#swarm)
  - [Kubernetes](#kubernetes)
- [Settings](#settings)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation first.

You will need a VirusTotal API key to contact their API (see [here](https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key)). The free API key is also working but you should check the terms of service and limits as described [here](https://support.virustotal.com/hc/en-us/articles/115002119845-What-is-the-difference-between-the-public-API-and-the-private-API-).

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker

```yaml
services:

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0-rc1
    ...
    environment:
      - USE_VIRUSTOTAL=yes
      - VIRUSTOTAL_API_KEY=mykey
    ...
```

## Swarm

```yaml
services:

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.6.0-rc1
    ...
    environment:
      - USE_VIRUSTOTAL=yes
      - VIRUSTOTAL_API_KEY=mykey
    ...
    networks:
      - bw-plugins
    ...

...
```

## Kubernetes

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/USE_VIRUSTOTAL: "yes"
    bunkerweb.io/VIRUSTOTAL_API_KEY: "mykey"
```

# Settings

| Setting                      | Default                             | Context   | Multiple | Description                                                                      |
| ---------------------------- | ----------------------------------- | --------- | -------- | -------------------------------------------------------------------------------- |
| `USE_VIRUSTOTAL`             | `no`                                | multisite | no       | Activate VirusTotal integration.                                                 |
| `VIRUSTOTAL_API_KEY`         |                                     | global    | no       | Key to authenticate with VirusTotal API.                                         |
| `VIRUSTOTAL_API_URL`         | `https://www.virustotal.com/api/v3` | global    | no       | Base URL of the VirusTotal API (or a VirusTotal-compatible endpoint).            |
| `VIRUSTOTAL_TIMEOUT`         | `1000`                              | global    | no       | Timeout in milliseconds for VirusTotal API requests.                             |
| `VIRUSTOTAL_SCAN_FILE`       | `yes`                               | multisite | no       | Activate automatic scan of uploaded files with VirusTotal (only existing files). |
| `VIRUSTOTAL_SCAN_IP`         | `yes`                               | multisite | no       | Activate automatic scan of uploaded ips with VirusTotal.                         |
| `VIRUSTOTAL_IP_SUSPICIOUS`   | `5`                                 | global    | no       | Minimum number of suspicious reports before considering IP as bad.               |
| `VIRUSTOTAL_IP_MALICIOUS`    | `3`                                 | global    | no       | Minimum number of malicious reports before considering IP as bad.                |
| `VIRUSTOTAL_FILE_SUSPICIOUS` | `5`                                 | global    | no       | Minimum number of suspicious reports before considering file as bad.             |
| `VIRUSTOTAL_FILE_MALICIOUS`  | `3`                                 | global    | no       | Minimum number of malicious reports before considering file as bad.              |
