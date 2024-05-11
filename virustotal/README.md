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
  - [Docker](#docker)
  - [Swarm](#swarm)
  - [Kubernetes](#kubernetes)
- [Settings](#settings)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation first.

You will need a VirusTotal API key to contact their API (see [here](https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key)). The free API key is also working but you should check the terms of service and limits as described [here](https://support.virustotal.com/hc/en-us/articles/115002119845-What-is-the-difference-between-the-public-API-and-the-private-API-).

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker

```yaml
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.5.6
    ...
    environment:
      - USE_VIRUSTOTAL=yes
      - VIRUSTOTAL_API_KEY=mykey
    ...
```

## Swarm

```yaml
version: '3'

services:

  mybunker:
    image: bunkerity/bunkerweb:1.5.6
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

|          Setting           |Default| Context |Multiple|                                  Description                                   |
|----------------------------|-------|---------|--------|--------------------------------------------------------------------------------|
|`USE_VIRUSTOTAL`            |`no`   |multisite|no      |Activate VirusTotal integration.                                                |
|`VIRUSTOTAL_API_KEY`        |       |global   |no      |Key to authenticate with VirusTotal API.                                        |
|`VIRUSTOTAL_SCAN_FILE`      |`yes`  |multisite|no      |Activate automatic scan of uploaded files with VirusTotal (only existing files).|
|`VIRUSTOTAL_SCAN_IP`        |`yes`  |multisite|no      |Activate automatic scan of uploaded ips with VirusTotal.                        |
|`VIRUSTOTAL_IP_SUSPICIOUS`  |`5`    |global   |no      |Minimum number of suspicious reports before considering IP as bad.              |
|`VIRUSTOTAL_IP_MALICIOUS`   |`3`    |global   |no      |Minimum number of malicious reports before considering IP as bad.               |
|`VIRUSTOTAL_FILE_SUSPICIOUS`|`5`    |global   |no      |Minimum number of suspicious reports before considering file as bad.            |
|`VIRUSTOTAL_FILE_MALICIOUS` |`3`    |global   |no      |Minimum number of malicious reports before considering file as bad.             |
