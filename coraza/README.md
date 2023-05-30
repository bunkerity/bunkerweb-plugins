# Coraza plugin

<p align="center">
	<img alt="BunkerWeb Coraza diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/dev/coraza/docs/diagram.png" />
</p>


This [BunkerWeb](https://www.bunkerweb.io) will act as a Library of rule that aim to detect and deny malicious requests 

# Table of contents

- [Coraza plugin](#coraza-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  * [Docker](#docker)
  * [Dockerfile](#dockerfile)
- [Settings](#settings)
  * [Plugin (BunkerWeb)](#plugin--bunkerweb-)
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
    image: bunkerity/bunkerweb:1.5.0
    ...
    environment:
      - USE_CORAZA: "yes"
      - USE_MODSECURITY: "no"
      - USE_MODSECURITY_CRS: "no"
    ...
    bw-scheduler:
        build:
            context: .
            dockerfile: src/scheduler/Dockerfile

    ...
    golang:
    build:
      context: .
      dockerfile: Dockerfile
    networks:
      - bw-services

```

## golang Dockerfile

```yaml

FROM golang:1.20-alpine
WORKDIR /app
COPY ./bw-data/plugins/coraza/confs/ /app
RUN apk add git wget tar 
RUN go install github.com/corazawaf/coraza-access
RUN go mod tidy 
RUN apk remove git wget tar
CMD ["go", "run", "/app/."]

```
# Settings

## Plugin (BunkerWeb)

| Setting      | Default                  | Description                                                                                    |
| :----------: | :----------------------: | :--------------------------------------------------------------------------------------------- |
| `USE_CORAZA` | `no`                     | When set to `yes`, requests will be checked by coraza.                      |
| `CORAZA_API` | `http://bunkerweb-golang-1:8090` | Address of the coraza library (request will be redirected there). |

! Disclamer the `CORAZA_API` port (by default 8090) can't be modified only in the plugin.json you also need to change it in the main.go (bw-data/plugins/coraza/confs/main.go)

# TODO

Fix the port problem.

Add the conf request to personalize the coreruleset and other parameters directly from bunkerweb (not by hands).

