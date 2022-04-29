# VirusTotal plugin

## Description

This [BunkerWeb](https://www.bunkerweb.io) plugin will automatically check if any uploaded file is already uploaded on VirusTotal and if that's the case will deny the request in case it's detected by some antivirus.

TODO : diagram

## Prerequisites

Please read the [plugins section](https://docs.bunkerweb.io/plugins) of the BunkerWeb documentation first.

You will need a VirusTotal API key to contact their API, you will find more information [here](https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key). Please note that free API key have constraints and limits as shown [here](https://support.virustotal.com/hc/en-us/articles/115002119845-What-is-the-difference-between-the-public-API-and-the-private-API-).

Please note that an additionnal service named **bunkerweb-virustotal** is required : it's a simple REST API that will handle the checks to the VirusTotal API. A redis service is also recommended to cache VirusTotal API results in case high performance is needed (it will also save you some requests made to the VT API by the way).

## Setup

### Docker

### Docker autoconf

### Swarm

### Kubernetes

## Settings

### Plugin

### bunkerweb-virustotal

## TODO

* Upload files to VT
* Test and document clustered mode
* Additional security checks like IP