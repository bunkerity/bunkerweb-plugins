# CrowdSec plugin

<p align="center">
	<img alt="BunkerWeb CrowdSec diagram" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/crowdsec/docs/diagram.svg" />
</p>

This [BunkerWeb](https://www.bunkerweb.io/?utm_campaign=self&utm_source=github) plugin acts as a [CrowdSec](https://crowdsec.net/) bouncer. It will deny requests based on the decision of your CrowdSec API. Not only you will benefit from the crowdsourced blacklist, you can also configure [scenarios](https://docs.crowdsec.net/docs/concepts#scenarios) to automatically ban IPs based on suspicious behaviors.

# Table of contents

- [CrowdSec plugin](#crowdsec-plugin)
- [Table of contents](#table-of-contents)
- [Prerequisites](#prerequisites)
  - [CrowdSec](#crowdsec)
    - [Optional : Application Security Component](#optional--application-security-component)
  - [Syslog](#syslog)
- [Setup](#setup)
  - [Docker/Swarm](#dockerswarm)
  - [Linux](#linux)
    - [Optional : Application Security Component](#optional--application-security-component-1)
    - [Linux Configuration](#linux-configuration)
  - [Kubernetes](#kubernetes)
- [Settings](#settings)

# Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation first and refer to the [CrowdSec documentation](https://docs.crowdsec.net/) if you are not familiar with it.

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

See the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the BunkerWeb documentation for the installation procedure depending on your integration.

## Docker/Swarm

```yaml
services:
  ...
    # BunkerWeb services
    environment:
      ...
      USE_CROWDSEC: "yes"
      CROWDSEC_API: "http://crowdsec:8080" # This is the address of the CrowdSec container API in the same network
      CROWDSEC_APPSEC_URL: "http://crowdsec:7422" # Comment if you don't want to use the AppSec Component
      CROWDSEC_API_KEY: "s3cr3tb0unc3rk3y" # Remember to set a stronger key for the bouncer

  ...

  crowdsec:
    image: crowdsecurity/crowdsec:v1.6.2 # Use the latest version but always pin the version for a better stability/security
    volumes:
      - cs-data:/var/lib/crowdsec/data # To persist the CrowdSec data
      - bw-logs:/var/log:ro # The logs of BunkerWeb for CrowdSec to parse
      - ./acquis.yaml:/etc/crowdsec/acquis.yaml # The acquisition file for BunkerWeb logs
      - ./appsec.yaml:/etc/crowdsec/acquis.d/appsec.yaml # Comment if you don't want to use the AppSec Component
    environment:
      BOUNCER_KEY_bunkerweb: "s3cr3tb0unc3rk3y" # Remember to set a stronger key for the bouncer
      COLLECTIONS: "crowdsecurity/nginx crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules"
      #   COLLECTIONS: "crowdsecurity/nginx" # If you don't want to use the AppSec Component use this line instead
    networks:
      - bw-plugins

  syslog:
    image: balabit/syslog-ng:4.7.1 # Use the latest version but always pin the version for a better stability/security
    # image: lscr.io/linuxserver/syslog-ng:4.7.1-r1-ls116 # For aarch64 architecture
    command: --no-caps
    volumes:
      - bw-logs:/var/log # The logs of BunkerWeb for syslog-ng to store
      - ./syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf # The syslog-ng configuration file
    networks:
      bw-plugins:
        ipv4_address: 10.10.10.254 # The IP address of the syslog service so BunkerWeb can send logs to it

networks:
  # BunkerWeb networks
  ...
  bw-plugins:
    ipam:
      driver: default
      config:
        - subnet: 10.10.10.0/24

volumes:
  bw-logs:
  cs-data:
```

## Linux

You'll need to install CrowdSec and configure it to parse BunkerWeb logs. To do so, you can follow the [official documentation](https://doc.crowdsec.net/docs/getting_started/install_crowdsec).

For CrowdSec to parse BunkerWeb logs, you have to add the following lines to your acquisition file located in `/etc/crowdsec/acquis.yaml` :

```yaml
filenames:
  - /var/log/bunkerweb/access.log
  - /var/log/bunkerweb/error.log
  - /var/log/bunkerweb/modsec_audit.log
labels:
  type: nginx
```

Now we have to add our custom bouncer to the CrowdSec API. To do so, you can use the `cscli` tool :

```shell
sudo cscli bouncers add crowdsec-bunkerweb-bouncer/v1.6
```

> [!IMPORTANT]
> Keep the key generated by the `cscli` command, you will need it later.

Now restart the CrowdSec service :

```shell
sudo systemctl restart crowdsec
```

### Optional : Application Security Component

If you want to use the AppSec Component, you will need to create another acquisition file for it located in `/etc/crowdsec/acquis.d/appsec.yaml` :

```yaml
appsec_config: crowdsecurity/appsec-default
labels:
  type: appsec
listen_addr: 127.0.0.1:7422
source: appsec
```

And you will need to install the AppSec Component's collections :

```shell
sudo cscli collections install crowdsecurity/appsec-virtual-patching
sudo cscli collections install crowdsecurity/appsec-generic-rules
```

Now you just have to restart the CrowdSec service :

```shell
sudo systemctl restart crowdsec
```

If you need more information about the AppSec Component, you can refer to the [official documentation](https://docs.crowdsec.net/docs/appsec/intro).

### Linux Configuration

Now you can configure the plugin by adding the following settings to your BunkerWeb configuration file :

```env
USE_CROWDSEC=yes
CROWDSEC_API=http://127.0.0.1:8080
CROWDSEC_API_KEY=<The key provided by cscli>
CROWDSEC_APPSEC_URL=http://127.0.0.1:7422 # Comment if you don't want to use the AppSec Component
```

And finally reload the BunkerWeb service :

```shell
sudo systemctl reload bunkerweb
```

## Kubernetes

> [!WARNING]
> Keep in mind that the helm chart is still in beta and may not be stable.

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
| `CROWDSEC_APPSEC_URL`             |  | global    | no       | URL of the Application Security Component.                                                                 |
| `CROWDSEC_APPSEC_FAILURE_ACTION`  | `passthrough`          | global    | no       | Behavior when the AppSec Component return a 500. Can let the request passthrough or deny it.               |
| `CROWDSEC_APPSEC_CONNECT_TIMEOUT` | `100`                  | global    | no       | The timeout in milliseconds of the connection between the remediation component and AppSec Component.      |
| `CROWDSEC_APPSEC_SEND_TIMEOUT`    | `100`                  | global    | no       | The timeout in milliseconds to send data from the remediation component to the AppSec Component.           |
| `CROWDSEC_APPSEC_PROCESS_TIMEOUT` | `500`                  | global    | no       | The timeout in milliseconds to process the request from the remediation component to the AppSec Component. |
| `CROWDSEC_ALWAYS_SEND_TO_APPSEC`  | `no`                   | global    | no       | Send the request to the AppSec Component even if there is a decision for the IP.                           |
| `CROWDSEC_APPSEC_SSL_VERIFY`      | `no`                   | global    | no       | Verify the AppSec Component SSL certificate validity.                                                      |
