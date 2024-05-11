# Coraza plugin

<p align="center">
	<img alt="BunkerWeb Coraza diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/coraza/docs/diagram.svg" />
</p>

This [Plugin](https://www.bunkerweb.io/latest/plugins) will act as a Library of rule that aim to detect and deny malicious requests

# Table of contents

- [Coraza plugin](#coraza-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Docker](#docker)
- [Settings](#settings)
  - [Plugin (BunkerWeb)](#plugin--bunkerweb-)
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
    image: bunkerity/bunkerweb:1.5.6
    ...
    environment:
      - USE_MODSECURITY=no # We don't need modsecurity anymore
      - USE_CORAZA=yes
      - CORAZA_API=http://bw-coraza:8080
    ...
  bw-coraza:
    image: bunkerity/bunkerweb-coraza:latest
    networks:
      - bw-universe

```

# Settings

|  Setting   |        Default        | Context |Multiple|        Description        |
|------------|-----------------------|---------|--------|---------------------------|
|`USE_CORAZA`|`no`                   |multisite|no      |Activate Coraza library    |
|`CORAZA_API`|`http://bw-coraza:8080`|global   |no      |hostname of the CORAZA API.|

# TODO

- Don't use API container
- More documentation
