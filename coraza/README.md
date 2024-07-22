# Coraza plugin

<p align="center">
	<img alt="BunkerWeb Coraza diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/coraza/docs/diagram.svg" />
</p>

This [Plugin](https://www.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) will act as a Library of rule that aim to detect and deny malicious requests

# Table of contents

- [Coraza plugin](#coraza-plugin)
- [Table of contents](#table-of-contents)
- [Setup](#setup)
  - [Docker/Swarm](#dockerswarm)
- [Settings](#settings)
- [TODO](#todo)

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker/Swarm

```yaml
services:

  # BunkerWeb services
    ...
    environment:
      HTTP2: "no" # The Coraza plugin doesn't support HTTP2 yet
      USE_MODSECURITY: "no" # We don't need ModSecurity anymore
      USE_CORAZA: "yes"
      CORAZA_API: "http://bw-coraza:8080" # This is the address of the coraza container in the same network
    networks:
      - bw-plugins

  ...

  bw-coraza:
    image: bunkerity/bunkerweb-coraza:2.0
    networks:
      - bw-plugins

networks:
  # BunkerWeb networks
  ...
  bw-plugins:
    name: bw-plugins
```

# Settings

| Setting      | Default                 | Context   | Multiple | Description                 |
| ------------ | ----------------------- | --------- | -------- | --------------------------- |
| `USE_CORAZA` | `no`                    | multisite | no       | Activate Coraza library     |
| `CORAZA_API` | `http://bw-coraza:8080` | global    | no       | hostname of the CORAZA API. |

# TODO

- Don't use API container
- More documentation
