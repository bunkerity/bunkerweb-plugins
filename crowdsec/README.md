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
  - [Docker](#docker)
  - [Linux](#linux)
  - [Kubernetes](#kubernetes)
- [Settings](#settings)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation first and refer to the [CrowdSec documentation](https://docs.crowdsec.net/) if you are not familiar with it.

You will need to run CrowdSec instance and configure it to parse BunkerWeb logs. Because BunkerWeb is based on NGINX, you can use the `nginx` value for the `type` parameter in your acquisition file (assuming that BunkerWeb logs are stored "as is" without additional data) :

```yaml
filenames:
  - /var/log/bunkerweb.log
labels:
  type: nginx
```

For container-based integrations, we recommend you to redirect the logs of the BunkerWeb container to a syslog service that will store the logs so CrowdSec can access it easily. Here is an example configuration for syslog-ng that will store raw logs coming from BunkerWeb to a local `/var/log/bunkerweb.log` file :

```conf
@version: 4.6

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

log {
  source(s_net);
  destination(d_file);
};
```

# Setup

See the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker

```yaml
version: "3"

services:
  bunkerweb:
    image: bunkerity/bunkerweb:1.5.6
    ports:
      - 80:8080
      - 443:8443
    labels:
      - "bunkerweb.INSTANCE=yes"
    environment:
      - SERVER_NAME=www.example.com
      - USE_CROWDSEC=yes
      - CROWDSEC_API=http://crowdsec:8080
      - CROWDSEC_API_KEY=s3cr3tb0unc3rk3y
      - USE_REVERSE_PROXY=yes
      - REVERSE_PROXY_URL=/
      - REVERSE_PROXY_HOST=http://myapp:8080
    networks:
      - bw-universe
      - bw-services
    logging:
      driver: syslog
      options:
        syslog-address: "udp://10.10.10.254:514"

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.5.6
    depends_on:
      - bunkerweb
      - bw-docker
    environment:
      - DOCKER_HOST=tcp://bw-docker:2375
    networks:
      - bw-universe
      - bw-docker

  bw-docker:
    image: tecnativa/docker-socket-proxy:nightly
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CONTAINERS=1
      - LOG_LEVEL=warning
    networks:
      - bw-docker

  crowdsec:
    image: crowdsecurity/crowdsec:v1.6.0
    volumes:
      - cs-data:/var/lib/crowdsec/data
      - ./acquis.yaml:/etc/crowdsec/acquis.yaml
      - bw-logs:/var/log:ro
    environment:
      - BOUNCER_KEY_bunkerweb=s3cr3tb0unc3rk3y
      - COLLECTIONS=crowdsecurity/nginx
    networks:
      - bw-universe

  syslog:
    image: balabit/syslog-ng:4.6.0
    volumes:
      - ./syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf
      - bw-logs:/var/log
    networks:
      bw-universe:
        ipv4_address: 10.10.10.254

  myapp:
    image: nginxdemos/nginx-hello
    networks:
      - bw-services

networks:
  bw-docker:
  bw-services:
  bw-universe:
    ipam:
      driver: default
      config:
        - subnet: 10.10.10.0/24

volumes:
  bw-data:
  bw-logs:
  cs-data:
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

And finally you can configure the plugin :

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    bunkerweb.io/USE_CROWDSEC: "yes"
    bunkerweb.io/CROWDSEC_API: "http://crowdsec-service.default.svc.cluster.local"
    bunkerweb.io/CROWDSEC_API_KEY: "s3cr3tb0unc3rk3y"
```

# Settings

|             Setting             |       Default        | Context |Multiple|                      Description                       |
|---------------------------------|----------------------|---------|--------|--------------------------------------------------------|
|`USE_CROWDSEC`                   |`no`                  |multisite|no      |Activate CrowdSec bouncer.                              |
|`CROWDSEC_API`                   |`http://crowdsec:8080`|global   |no      |Address of the CrowdSec API.                            |
|`CROWDSEC_API_KEY`               |                      |global   |no      |Key for the CrowdSec API given by cscli bouncer add.    |
|`CROWDSEC_MODE`                  |`live`                |global   |no      |Mode of the CrowdSec API (live or stream).              |
|`CROWDSEC_REQUEST_TIMEOUT`       |`500`                 |global   |no      |Bouncer's request timeout in milliseconds (live mode).  |
|`CROWDSEC_STREAM_REQUEST_TIMEOUT`|`15000`               |global   |no      |Bouncer's request timeout in milliseconds (stream mode).|
|`CROWDSEC_UPDATE_FREQUENCY`      |`10`                  |global   |no      |Bouncer's update frequency in stream mode, in second.   |
|`CROWDSEC_CACHE_EXPIRATION`      |`1`                   |global   |no      |Bouncer's cache expiration in live mode, in second.     |
