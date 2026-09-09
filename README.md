<p align="center">
	<img alt="BunkerWeb logo" src="https://github.com/bunkerity/bunkerweb-plugins/raw/main/logo.png" />
</p>

<p align="center">
	<img src="https://img.shields.io/badge/bunkerweb_plugins-1.12-blue" />
	<img src="https://img.shields.io/github/last-commit/bunkerity/bunkerweb-plugins" />
	<img src="https://img.shields.io/github/actions/workflow/status/bunkerity/bunkerweb-plugins/tests.yml?branch=dev&label=CI%2FCD%20dev" />
	<img src="https://img.shields.io/github/actions/workflow/status/bunkerity/bunkerweb-plugins/tests.yml?branch=main&label=CI%2FCD%20main" />
	<img src="https://img.shields.io/github/issues/bunkerity/bunkerweb-plugins">
	<img src="https://img.shields.io/github/issues-pr/bunkerity/bunkerweb-plugins">
	<a href="https://score.getplumber.io/github.com/bunkerity/bunkerweb-plugins"><img src="https://score.getplumber.io/github.com/bunkerity/bunkerweb-plugins.svg" alt="Plumber CI/CD security score" /></a>
</p>

This repository contains "official" plugins for the [BunkerWeb solution](https://github.com/bunkerity/bunkerweb). If you don't already know BunkerWeb, you should first read the [documentation](https://docs.bunkerweb.io/?utm_campaign=self&utm_source=github).

# Prerequisites

The installation of external plugins is covered in the [plugins section](https://docs.bunkerweb.io/latest/plugins/?utm_campaign=self&utm_source=github) of the documentation.

# Plugins

Each plugin is located in a subdirectory of this repository. A README file located in each subdirectory contains documentation about the plugin. Here is the list :

- [Authentik](https://github.com/bunkerity/bunkerweb-plugins/tree/main/authentik)
- [ClamAV](https://github.com/bunkerity/bunkerweb-plugins/tree/main/clamav)
- [Cloudflare](https://github.com/bunkerity/bunkerweb-plugins/tree/main/cloudflare)
- [Coraza](https://github.com/bunkerity/bunkerweb-plugins/tree/main/coraza)
- [Discord](https://github.com/bunkerity/bunkerweb-plugins/tree/main/discord)
- [Matrix](https://github.com/bunkerity/bunkerweb-plugins/tree/main/matrix)
- [SentinelOne](https://github.com/bunkerity/bunkerweb-plugins/tree/main/sentinelone)
- [Slack](https://github.com/bunkerity/bunkerweb-plugins/tree/main/slack)
- [SysWarden](https://github.com/bunkerity/bunkerweb-plugins/tree/main/syswarden)
- [VirusTotal](https://github.com/bunkerity/bunkerweb-plugins/tree/main/virustotal)
- [WebHook](https://github.com/bunkerity/bunkerweb-plugins/tree/main/webhook)

# Compatibility and releases

Release **1.12** supports **BunkerWeb 1.6.14**. The compatibility declaration
applies to all 11 plugins listed above. Historical declarations are preserved in
[COMPATIBILITY.json](COMPATIBILITY.json); older BunkerWeb versions have not been
revalidated for 1.12.

To prepare a release, run `bash misc/update_version.sh <version>` from the repository
root and add the matching version to `COMPATIBILITY.json`, listing the BunkerWeb
versions validated by the integration suite. CI checks that every plugin uses the
same version and that its compatibility entry includes the resolved BunkerWeb tag.

After `Tests` succeeds on `main`, the release workflow creates a draft with generated
release notes, unless that version already has a release or draft. It verifies that
the checked-out commit matches the tested commit before reading release metadata.
A maintainer reviews and publishes the draft.

# Support

## Professional

We offer professional services related to BunkerWeb like :

- Consulting
- Support
- Custom development
- Partnership

Please contact us at contact \[@\] bunkerity.com if you are interested.

## Community

To get free community support you can use the following media :

- The #help channel of BunkerWeb in the [Discord server](https://bunkerity.discord.com/?utm_campaign=self&utm_source=github)
- The help category of [GitHub discussions](https://github.com/bunkerity/bunkerweb-plugins/discussions)
- The [/r/BunkerWeb](https://www.reddit.com/r/BunkerWeb) subreddit
- The [Server Fault](https://serverfault.com/) and [Super User](https://superuser.com/) forums

Please don't use [GitHub issues](https://github.com/bunkerity/bunkerweb-plugins/issues) to ask for help, use it only for bug reports and feature requests.

# License

This project is licensed under the terms of the [GNU Affero General Public License (AGPL) version 3](https://github.com/bunkerity/bunkerweb-plugins/tree/main/LICENSE.md).

# Contribute

If you would like to contribute to the plugins you can read the [contributing guidelines](https://github.com/bunkerity/bunkerweb-plugins/tree/main/CONTRIBUTING.md) to get started.

# Security policy

We take security bugs as serious issues and encourage responsible disclosure, see our [security policy](https://github.com/bunkerity/bunkerweb-plugins/tree/main/SECURITY.md) for more information.
