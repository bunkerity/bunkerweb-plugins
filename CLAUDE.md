# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

Official external plugins for [BunkerWeb](https://github.com/bunkerity/bunkerweb). Each top-level directory (`clamav/`, `coraza/`, `discord/`, `slack/`, `virustotal/`, `webhook/`) is an independently-shipped plugin. There is no monorepo build — plugins are consumed by BunkerWeb at runtime by mounting the plugin directory into `/data/plugins` of the `bunkerweb-scheduler` container.

## Plugin anatomy

Every plugin follows the same BunkerWeb-imposed layout:

- `plugin.json` — id, name, version, `stream` (yes/no/partial), and the `settings` schema (each setting has `context` = `global`|`multisite`, `default`, `regex`, UI metadata). BunkerWeb reads this to register settings and render the UI.
- `<plugin>.lua` — main logic; requires `bunkerweb.plugin` and subclasses it via `middleclass`. Hook methods (`init_worker`, `access`, `log`, `preread`, etc.) return via `self:ret(ok, msg, [status])`. Runs inside OpenResty in the BunkerWeb nginx container.
- `ui/actions.py` — optional Python hooks for the BunkerWeb web UI. `pre_render(**kwargs)` returns card data; a function named after the plugin is called for the main page. `kwargs["bw_instances_utils"]` exposes BW helpers like `get_ping(service)`.
- `README.md` — user-facing docs; the settings table is generated from `plugin.json` via `.tests/misc/json2md.py` (run manually when settings change).
- `docs/diagram.drawio` + `docs/diagram.svg` — architecture diagram shipped with each plugin.

Coraza is special: it also ships `coraza/api/` — a standalone Go HTTP service (`main.go`, built by `coraza/api/Dockerfile`) that wraps `corazawaf/coraza/v3` and is called over HTTP by `coraza.lua`. Image is published as `bunkerity/bunkerweb-coraza`. CRS rules are vendored at build time by `crs.sh` (pinned to a commit hash, `.git` stripped).

## Versioning — two different version numbers

There are **two unrelated version streams**, easy to confuse:

1. **Individual plugin version** in each `plugin.json` (currently `1.10`). Bump with `./misc/update_version.sh <new_version>` from the repo root — it rewrites every `plugin.json` and the README badge in place.
2. **Plugins-collection version** in `COMPATIBILITY.json`, which maps a collection version to the BunkerWeb versions it supports (e.g. `"1.8": ["1.6.0", ...]`). This is the version shown in the README badge and controls compatibility gates.

When bumping, check both — the README badge is tied to (2), while `plugin.json` uses (1).

## Testing

There is no unit-test framework. Tests are end-to-end integration tests under `.tests/`:

- `./.tests/bw.sh <bw_tag>` pulls `bunkerity/bunkerweb:<tag>` + `bunkerweb-scheduler:<tag>` and retags them as `bunkerweb:tests` / `bunkerweb-scheduler:tests`. Must run first.
- `./.tests/clamav.sh`, `./.tests/coraza.sh`, `./.tests/virustotal.sh` each: copy the plugin into `/tmp/bunkerweb-plugins/<plugin>/bw-data/plugins` (owned `101:101`), copy `.tests/<plugin>/docker-compose.yml`, `sed` the compose file to use the `:tests` tagged images, then `docker compose up --build -d` and poll with `curl`. EICAR file is downloaded for ClamAV; VirusTotal requires `VIRUSTOTAL_API_KEY` env var.
- `.tests/utils.sh` provides `do_and_check_cmd` (runs a command, echoes output on failure, exits on non-zero) and `git_secure_clone` (pinned-commit clone helper). Source it with `. .tests/utils.sh`.
- Run a single plugin's tests: `./.tests/bw.sh dev && ./.tests/clamav.sh` (or `coraza`/`virustotal`). Pass `verbose` as `$1` to dump compose logs on success.
- Tests need `sudo` (for chowning to BW's uid 101) and a working Docker daemon. They leave state in `/tmp/bunkerweb-plugins/` — the scripts clean it at start, but `docker compose down -v` is the safe manual reset.

Discord, Slack, and Webhook have no automated tests — they're exercised by manually pointing a real BunkerWeb instance at a webhook URL.

## CI/CD (`.github/workflows/tests.yml`)

Runs on push to `dev` and `main`. Picks BW tag from branch: `main` → `1.6.1`, `dev` → `dev`. Runs CodeQL, then `bw.sh` → `clamav.sh` → `coraza.sh` → `virustotal.sh` sequentially. On `main` only, `./.tests/build-push.sh 1.6.1` builds and pushes the `bunkerweb-coraza` image. **If you update the pinned BW version, update the hardcoded `1.6.1` in `tests.yml` too** — it is not read from `COMPATIBILITY.json`.

## Linting — pre-commit is the source of truth

`.pre-commit-config.yaml` pins every linter to a frozen SHA. Install once with `pre-commit install`, then `pre-commit run --all-files` before committing. The stack:

- `black` (Python, py3.9) — configured in `pyproject.toml` with `line-length = 160`
- `flake8` — `--max-line-length=250 --ignore=E266,E402,E722,W503`
- `stylua` — config in `stylua.toml`
- `luacheck` — config in `.luacheckrc`, run with `--std min --codes --ranges --no-cache`
- `prettier`, `shellcheck`, `codespell`, `gitleaks`, standard pre-commit hygiene hooks

`coraza/api/coreruleset/**` and `LICENSE.md` are excluded from all hooks.

## Writing Lua plugin code — conventions to follow

- Always subclass via `local <name> = class("<name>", plugin)` and call `plugin.initialize(self, "<id>", ctx)` in `initialize(self, ctx)`.
- Every hook method returns `self:ret(ok_bool, msg, [http_status])`. To deny a request, return `self:ret(true, "reason", utils.get_deny_status())`.
- Gate expensive work at `init_worker` with `utils.has_variable("USE_<PLUGIN>", "yes")` — avoids connecting to upstream services when the plugin is globally disabled. Skip when `self.is_loading` is true.
- Use `ngx.socket` for TCP (see `clamav.lua` INSTREAM protocol) and `resty.http` for HTTP upstreams. Prefer `resty.upload` for streaming request bodies (`clamav.lua` is the reference).
- Cache API responses (SHA-512 of body for file scans) — `virustotal.lua` is the pattern.

## Pull requests & commits

- Default branch for PRs is `main`; active development lands on `dev` first.
- Commits follow conventional-commits style (`feat:`, `fix:`, `refactor:`, `ci/cd -`). See `git log` for prior examples.
- CONTRIBUTING.md requires an issue before non-trivial PRs.
