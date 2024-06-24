# CrowdSec plugin

<p align="center">
	<img alt="BunkerWeb CrowdSec diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/crowdsec/docs/diagram.svg" />
</p>

This [BunkerWeb](https://www.bunkerweb.io) plugin acts as a [CrowdSec](https://crowdsec.net/) bouncer. It will deny requests based on the decision of your CrowdSec API. Not only you will benefinit from the crowdsourced blacklist, you can also configure [scenarios](https://docs.crowdsec.net/docs/concepts#scenarios) to automatically ban IPs based on suspicious behaviors.

# Table of contents

- [CrowdSec plugin](#crowdsec-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
  - [CrowdSec](#crowdsec)
    - [Optional : Application Security Component](#optional--application-security-component)
  - [Syslog](#syslog)
- [Setup](#setup)
  - [Docker](#docker)
  - [Kubernetes](#kubernetes)
- [Settings](#settings)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins) of the BunkerWeb documentation first and refer to the [CrowdSec documentation](https://docs.crowdsec.net/) if you are not familiar with it.

## CrowdSec

You will need to run CrowdSec instance and configure it to parse BunkerWeb logs. Because BunkerWeb is based on NGINX, you can use the `nginx` value for the `type` parameter in your acquisition file (assuming that BunkerWeb logs are stored "as is" without additional data) :

```yaml
filenames:
  - /var/log/bunkerweb.log
labels:
  type: nginx
```

### Optional : Application Security Component

CrowdSec also provides an [Application Security Component](https://docs.crowdsec.net/docs/appsec/intro) that can be used to protect your application from attacks. You can configure the plugin to send requests to the AppSec Component for further analysis. If you want to use it, you will need to create another acquisition file for the AppSec Component :

```yaml
appsec_config: crowdsecurity/appsec-default
labels:
  type: appsec
listen_addr: 0.0.0.0:7422
source: appsec
```

## Syslog

For container-based integrations, we recommend you to redirect the logs of the BunkerWeb container to a syslog service that will store the logs so CrowdSec can access it easily. Here is an example configuration for syslog-ng that will store raw logs coming from BunkerWeb to a local `/var/log/bunkerweb.log` file :

```conf
@version: 4.7

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
    image: bunkerity/bunkerweb:1.5.8
    ports:
      - 80:8080
      - 443:8443
    labels:
      - "bunkerweb.INSTANCE=yes"
    environment:
      - SERVER_NAME=www.example.com
      - API_WHITELIST_IP=127.0.0.0/24 10.20.30.0/24
      - USE_CROWDSEC=yes
      - CROWDSEC_API=http://crowdsec:8080
      - CROWDSEC_APPSEC_URL=http://crowdsec:7422
      - CROWDSEC_API_KEY=s3cr3tb0unc3rk3y
      - USE_REVERSE_PROXY=yes
      - REVERSE_PROXY_URL=/
      - REVERSE_PROXY_HOST=http://myapp:8080
    networks:
      - bw-universe
      - bw-services
      - bw-plugins
    logging:
      driver: syslog
      options:
        syslog-address: "udp://10.10.10.254:514"

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:1.5.8
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
    image: crowdsecurity/crowdsec:v1.6.2
    volumes:
      - cs-data:/var/lib/crowdsec/data
      - ./acquis.yaml:/etc/crowdsec/acquis.yaml
      - ./appsec.yaml:/etc/crowdsec/acquis.d/appsec.yaml # Comment if you don't want to use the AppSec Component
      - bw-logs:/var/log:ro
    environment:
      - BOUNCER_KEY_bunkerweb=s3cr3tb0unc3rk3y
      - COLLECTIONS=crowdsecurity/nginx crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
    networks:
      - bw-plugins

  syslog:
    image: balabit/syslog-ng:4.7.1
    volumes:
      - ./syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf
      - bw-logs:/var/log
    networks:
      bw-plugins:
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
        - subnet: 10.20.30.0/24
  bw-plugins:
    ipam:
      driver: default
      config:
        - subnet: 10.10.10.0/24

volumes:
  bw-data:
  bw-logs:
  cs-data:
```

> [!TIP]
> The `balabit/syslog-ng` image used in the example is only compatible with amd64 architecture. If you want to use an arm64 compatible image, you can use `lscr.io/linuxserver/syslog-ng` instead.

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

| Setting                           | Default                | Context   | Multiple | Description                                                                                                |
| --------------------------------- | ---------------------- | --------- | -------- | ---------------------------------------------------------------------------------------------------------- |
| `USE_CROWDSEC`                    | `no`                   | multisite | no       | Activate CrowdSec bouncer.                                                                                 |
| `CROWDSEC_API`                    | `http://crowdsec:8080` | global    | no       | Address of the CrowdSec API.                                                                               |
| `CROWDSEC_API_KEY`                |                        | global    | no       | Key for the CrowdSec API given by cscli bouncer add.                                                       |
| `CROWDSEC_MODE`                   | `live`                 | global    | no       | Mode of the CrowdSec API (live or stream).                                                                 |
| `CROWDSEC_REQUEST_TIMEOUT`        | `500`                  | global    | no       | Timeout in milliseconds for the HTTP requests done by the bouncer to query CrowdSec local API.             |
| `CROWDSEC_EXCLUDE_LOCATION`       |                        | global    | no       | The locations to exclude while bouncing. It is a list of location, separated by commas.                    |
| `CROWDSEC_CACHE_EXPIRATION`       | `1`                    | global    | no       | The cache expiration, in second, for IPs that the bouncer store in cache in live mode.                     |
| `CROWDSEC_UPDATE_FREQUENCY`       | `10`                   | global    | no       | The frequency of update, in second, to pull new/old IPs from the CrowdSec local API.                       |
| `CROWDSEC_REDIRECT_LOCATION`      |                        | global    | no       | The location to redirect the user when there is a ban.                                                     |
| `CROWDSEC_RET_CODE`               | `403`                  | global    | no       | The HTTP code to return for IPs that trigger a ban remediation. (default: 403)                             |
| `CROWDSEC_APPSEC_URL`             | `http://crowdsec:7422` | global    | no       | URL of the Application Security Component.                                                                 |
| `CROWDSEC_APPSEC_FAILURE_ACTION`  | `passthrough`          | global    | no       | Behavior when the AppSec Component return a 500. Can let the request passthrough or deny it.               |
| `CROWDSEC_APPSEC_CONNECT_TIMEOUT` | `100`                  | global    | no       | The timeout in milliseconds of the connection between the remediation component and AppSec Component.      |
| `CROWDSEC_APPSEC_SEND_TIMEOUT`    | `100`                  | global    | no       | The timeout in milliseconds to send data from the remediation component to the AppSec Component.           |
| `CROWDSEC_APPSEC_PROCESS_TIMEOUT` | `500`                  | global    | no       | The timeout in milliseconds to process the request from the remediation component to the AppSec Component. |
| `CROWDSEC_ALWAYS_SEND_TO_APPSEC`  | `false`                | global    | no       | Send the request to the AppSec Component even if there is a decision for the IP.                           |
| `CROWDSEC_APPSEC_SSL_VERIFY`      | `false`                | global    | no       | Verify the AppSec Component SSL certificate validity.                                                      |
