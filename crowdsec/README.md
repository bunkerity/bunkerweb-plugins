# CrowdSec plugin

<p align="center">
	<img alt="BunkerWeb CrowdSec diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/crowdsec/docs/diagram.svg" />
</p>

This [BunkerWeb](https://www.bunkerweb.io) plugin acts as a [CrowdSec](https://crowdsec.net/) bouncer. It will deny requests based on the decision of your CrowdSec API. Not only you will benefinit from the crowdsourced blacklist, you can also configure [scenarios](https://docs.crowdsec.net/docs/concepts#scenarios) to automatically ban IPs based on suspicious behaviors.

# Table of contents

- [CrowdSec plugin](#crowdsec-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  * [Docker](#docker)
  * [Swarm](#swarm)
  * [Kubernetes](#kubernetes)
- [Settings](#settings)
- [TODO](#todo)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/plugins) of the BunkerWeb documentation first and refer to the [CrowdSec documentation](https://docs.crowdsec.net/) if you are not familiar with it.

You will need to run CrowdSec instance and configure it to parse BunkerWeb logs. Because BunkerWeb is based on NGINX, you can use the `nginx` value for the `type` parameter in your acquisition file (assuming that BunkerWeb logs are stored "as is" without additionnal data) :
```yaml
filenames:
  - /var/log/bunkerweb.log
labels:
  type: nginx
```

For container-based integrations, we recommend you to redirect the logs of the BunkerWeb container to a syslog service that will store the logs so CrowdSec can access it easily. Here is an example configuration for syslog-ng that will store raw logs coming from BunkerWeb to a local `/var/log/bunkerweb.log` file :
```conf
@version: 3.36

source s_net {
  udp(
    ip("0.0.0.0")
  );
};

template t_imp {
  template("$MSG\n");
  template_escape(no);
};

destination d_file {
  file("/var/log/bunkerweb.log" template(t_imp));
};

log { source(s_net); destination(d_file); };
```

# Setup

See the [plugins section](https://docs.bunkerweb.io/plugins) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker

```yaml
version: '3'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.4.0
    ports:
      - 80:8080
      - 443:8443
    ...
    environment:
      - USE_CROWDSEC=yes
      - CROWDSEC_API=http://crowdsec:8080
      - CROWDSEC_API_KEY=s3cr3tb0unc3rk3y
    networks:
      - bw-plugins
    logging:
      driver: syslog
      options:
        syslog-address: "udp://10.10.10.254:514"
    ...

  crowdsec:
    image: crowdsecurity/crowdsec:v1.3.4
    volumes:
      - cs-data:/var/lib/crowdsec/data
      - ./acquis.yaml:/etc/crowdsec/acquis.yaml
      - bw-logs:/var/log:ro
    environment:
      - BOUNCER_KEY_bunkerweb=s3cr3tb0unc3rk3y
      - COLLECTIONS=crowdsecurity/nginx
    networks:
      - bw-plugins

  syslog:
    image: balabit/syslog-ng:3.36.1
    volumes:
      - ./syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf
      - bw-logs:/var/log
    networks:
      bw-plugins:
        ipv4_address: 10.10.10.254

...

networks:
  bw-plugins:
    ipam:
      driver: default
      config:
        - subnet: 10.10.10.0/24

volumes:
  bw-logs:
  cs-data:

...
```

## Swarm

Unfortunately, Docker Swarm doesn't seam to support "affinity" for services on so we can't be sure that the **crowdsec** and the **syslog** service will be on the same machine and so will be able to share a volume. Another alternative would be to have a shared folder mounted on /shared for example.

```yaml
version: '3.5'

services:

  bunkerweb:
    image: bunkerity/bunkerweb:1.4.0
    ports:
      - 80:8080
      - 443:8443
    ...
    environment:
      - USE_CROWDSEC=yes
      - CROWDSEC_API=http://crowdsec:8080
      - CROWDSEC_API_KEY=s3cr3tb0unc3rk3y
    networks:
      - bw-plugins
    logging:
      driver: syslog
      options:
        syslog-address: "udp://10.10.10.254:514"
    ...

  crowdsec:
    image: crowdsecurity/crowdsec:v1.3.4
    volumes:
      - /shared/cs-data:/var/lib/crowdsec/data
      - /shared/acquis.yaml:/etc/crowdsec/acquis.yaml
      - /shared/logs:/var/log:ro
    environment:
      - BOUNCER_KEY_bunkerweb=s3cr3tb0unc3rk3y
      - COLLECTIONS=crowdsecurity/nginx
    networks:
      - bw-plugins

  syslog:
    image: balabit/syslog-ng:3.36.1
    volumes:
      - /shared/syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf
      - /shared/logs:/var/log
    networks:
      bw-plugins:
        ipv4_address: 10.10.10.254

...

networks:
  bw-plugins:
    driver: overlay
    attachable: true
    name: bw-plugins

...
```

## Kubernetes

The recommended way of installing CrowdSec in your Kubernetes cluster is by using their official [helm chart](https://github.com/crowdsecurity/helm-charts). You will find a tutorial [here](https://crowdsec.net/blog/kubernetes-crowdsec-integration/) for more information. By doing so, a syslog service is no more mandatory because agents will forward BunkerWeb logs to the CS API.

The first step is to add the CrowdSec chart repository :
```shell
helm repo add crowdsec https://crowdsecurity.github.io/helm-charts && helm repo update
```

Now we can create the config file named **crowdsec-values.yml** that will be used to configure the chart :
```yaml
agent:
  acquisition:
      # Namespace of BunkerWeb
    - namespace: default
      # Pod names of BunkerWeb
      podName: bunkerweb-*
      program: nginx
  env:
  - name: BOUNCER_KEY_bunkerweb
    value: "s3cr3tb0unc3rk3y"
  - name: COLLECTIONS
    value: "crowdsecurity/nginx"
```

After the **crowdsec-values.yml** file is created, you can now deploy the CrowdSec stack :
```shell
helm install crowdsec crowdsec/crowdsec -f crowdsec-values.yaml
```

 configure the plugin :
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/AUTOCONF: "yes"
    bunkerweb.io/USE_CROWDSEC: "yes"
    bunkerweb.io/CROWDSEC_API: "http://crowdsec-service.default.svc.cluster.local"
    bunkerweb.io/CROWDSEC_API_KEY: "s3cr3tb0unc3rk3y"
...
```

# Settings

| Setting            | Default                | Description                                                                      |
| :----------------: | :--------------------: | :------------------------------------------------------------------------------- |
| `USE_CROWDSEC`     | `no`                   | When set to `yes`, CrowdSec bouncer will be activated.                           |
| `CROWDSEC_API`     | `http://crowdsec:8080` | Address of the CrowdSec API.                                                     |
| `CROWDSEC_API_KEY` |                        | Bouncer key to use when contacting the API (must be created on the CS instance). |

# TODO

* Linux setup example
* Proper way for Swarm