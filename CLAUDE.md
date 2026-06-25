# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

Official external plugins for [BunkerWeb](https://github.com/bunkerity/bunkerweb). Each top-level directory (`authentik/`, `clamav/`, `coraza/`, `discord/`, `matrix/`, `slack/`, `virustotal/`, `webhook/`) is an independently-shipped plugin. There is no monorepo build — plugins are consumed by BunkerWeb at runtime by mounting the plugin directory into `/data/plugins` of the `bunkerweb-scheduler` container.

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

1. **Individual plugin version** in each `plugin.json` (currently `1.11`). Bump with `./misc/update_version.sh <new_version>` **run from the repo root** (it uses `find .` + `README.md` relative paths) — it rewrites every `plugin.json` **and the README badge** to that plugin version (see `misc/update_version.sh:17-18`).
2. **Plugins-collection version** in `COMPATIBILITY.json`, which maps a collection version (currently `1.8`) to the BunkerWeb versions it supports (e.g. `"1.8": ["1.6.0", ...]`). Controls compatibility gates.

These two streams are independent and `update_version.sh` only touches (1) — it now updates the README badge too (the badge's sed pattern was anchored on a leading `"` that never matched the shields.io URL, so the badge silently froze; fixed to anchor on `/badge/`, so it tracks the plugin version automatically). When bumping: run the script for (1), and edit `COMPATIBILITY.json` by hand for (2).

## Testing

Two layers: fast **unit tests** (no Docker) and **end-to-end integration tests** under `.tests/`.

### Unit tests (no Docker, run locally + in CI)

- **Go** — `coraza/api/main_test.go` covers the Go WAF service. Run `cd coraza/api && go test ./...`.
- **Python (pytest)** — `tests/test_ui_actions.py` parametrizes over every plugin's `ui/actions.py`; `tests/conftest.py` provides a `FakePingUtils` mock for `bw_instances_utils`. Run `pytest tests/ -q`.
- **Lua (busted)** — `spec/*_helpers_spec.lua` exercises the pure-logic helper modules (`authentik`, `clamav`, `discord`, `matrix`, `virustotal`) against `spec/helpers/fake_ngx.lua`. Run `busted`. This is why upstream-specific logic is factored into `<plugin>_helpers.lua` — so it's testable outside OpenResty.

### Integration tests (Docker, e2e)

- `./.tests/bw.sh <bw_tag>` pulls `bunkerity/bunkerweb:<tag>` + `bunkerweb-scheduler:<tag>` and retags them as `bunkerweb:tests` / `bunkerweb-scheduler:tests`. Must run first.
- Per-plugin scripts: `./.tests/clamav.sh`, `coraza.sh`, `virustotal.sh`, `authentik.sh`, and `notifier.sh` (the last covers discord/slack/webhook/matrix together in one multisite stack). Each copies the plugin into `/tmp/bunkerweb-plugins/<plugin>/bw-data/plugins` (owned `101:101`), copies `.tests/<plugin>/docker-compose.yml`, `sed`s it to the `:tests` tagged images, then `docker compose up --build -d` and polls with `curl`. EICAR file is downloaded for ClamAV; VirusTotal requires `VIRUSTOTAL_API_KEY`. Several use mock upstreams instead of the real service: `.tests/virustotal/vt-mock.conf`, `.tests/authentik/mock-outpost.conf`, `.tests/notifier/ratelimit.conf`.
- `.tests/utils.sh` provides `do_and_check_cmd` (runs a command, echoes output on failure, exits on non-zero) and `git_secure_clone` (pinned-commit clone helper). Source it with `. .tests/utils.sh`.
- Run a single plugin's e2e: `./.tests/bw.sh <bw_tag> && ./.tests/clamav.sh` (or `coraza`/`virustotal`/`authentik`/`notifier`). CI resolves `<bw_tag>` to the latest stable release; locally any pulled tag works (e.g. a stable `1.6.1`, or `dev` for the upcoming build). Pass `verbose` as `$1` to dump compose logs on success.
- Tests need `sudo` (for chowning to BW's uid 101) and a working Docker daemon. They leave state in `/tmp/bunkerweb-plugins/` — the scripts clean it at start, but `docker compose down -v` is the safe manual reset.

## CI/CD (`.github/workflows/tests.yml`)

Runs on push to `dev` and `main`. A `tag` job resolves the **latest stable BunkerWeb release** at runtime via the GitHub `releases/latest` API (`gh api repos/bunkerity/bunkerweb/releases/latest`, which excludes drafts and pre-releases; a leading `v` is stripped) and feeds that tag to every downstream job — same version on both branches, never pinned. Pipeline:

1. **codeql** — `.github/workflows/codeql.yml` (also runs weekly on a cron), matrix `[python, go]`.
2. **lint** — `pre-commit run --all-files`.
3. **unit** — matrix `[go, python, lua]` (the unit tests above).
4. **integration** — `needs: [tag, lint, unit]`, matrix `plugin: [clamav, coraza, virustotal, authentik, notifier]`; each runs `.tests/bw.sh <tag>` then `.tests/<plugin>.sh`.
5. **build-push** — `main` only: `./.tests/build-push.sh <tag>` builds and pushes the `bunkerweb-coraza` image.

There is **no pinned BW version** — the `tag` job always resolves the latest stable release, so the tests track upstream automatically (`COMPATIBILITY.json` is not consulted here). The resolved tag flows into `bw.sh` (pulls `bunkerity/bunkerweb[-scheduler]:<tag>`) and, on `main`, into `build-push.sh` (which also tags the pushed `bunkerweb-coraza` image with it). The job fails fast if the API returns an empty or pre-release (hyphenated) tag.

Two tradeoffs of tracking upstream: (1) the `dev` branch no longer tests against BunkerWeb's `dev` build, so a plugin change that relies on an unreleased BW feature gets no CI coverage until BW ships a stable release; (2) every `main` push republishes `bunkerweb-coraza:latest` (and `:<stable>`) — harmless here because that image is a self-contained Go binary + vendored CRS, independent of the BW base tag, so only the extra tag's value moves.

## Releasing (`.github/workflows/release.yml`)

Releases are cut automatically from `main`. After `Tests` succeeds there, a `Release` workflow (a `workflow_run` trigger on the `Tests` workflow) reads the plugin version from `plugin.json` and, if no release `v<version>` exists yet (**drafts included** — it matches `tag_name` via `gh api`, since a draft has no git tag), opens a **draft** GitHub release with `softprops/action-gh-release` and auto-generated notes. A maintainer reviews and publishes it; a push that doesn't bump the version is a no-op. Two consequences of the `workflow_run` model: the file only fires once it is on the default branch (`main`), and it can't be tested from `dev`. So **cutting a release = `./misc/update_version.sh <ver>` → merge to `main` → publish the draft** the workflow creates.

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
- Cache scan results keyed by the file's hash so identical uploads skip the upstream. `clamav.lua` hashes the body with **SHA-512** (`resty.sha512`); `virustotal.lua` uses **SHA-256** (`resty.sha256`, matching VT's file-id) with a 24h TTL — it's the reference for cached HTTP-API lookups.

## Plugin-specific notes

The "Plugin anatomy" layout and the Lua conventions above are shared by all plugins. The non-obvious, per-plugin logic lives in code — these pointers save a re-read:

- **coraza** — the only plugin with an external sidecar. `coraza.lua` talks HTTP to the Go service in `coraza/api/` (`/ping` health check, `/request` for the verdict; the service returns deny/msg). CRS rules are vendored at build time by `coraza/api/crs.sh`, **pinned to a commit hash** with `.git` stripped; the two-stage `coraza/api/Dockerfile` builds the Go binary (multiphase-evaluation build tag) and bakes the rules in. Bumping CRS = bump the hash in `crs.sh`. Image: `bunkerity/bunkerweb-coraza`.
- **clamav** — speaks ClamAV's **binary INSTREAM protocol** over `ngx.socket.tcp` (each chunk framed by a 4-byte big-endian length, terminated by a zero-length frame), not HTTP. Streams the request body via `resty.upload`, scanning only multipart parts that have a real filename (`Content-Disposition` parsing handles quoted, unquoted, and RFC 5987 `filename*`). SHA-512 cache (see above).
- **virustotal** — HTTP to VT API v3 with `VIRUSTOTAL_API_KEY`; scans files and/or IPs. Verdict logic is in `virustotal_helpers.lua` (`evaluate()` compares VT's suspicious/malicious counts to configurable thresholds) — unit-tested in `spec/virustotal_helpers_spec.lua`. SHA-256 cache, 24h TTL. No usable ping endpoint, so `init_worker` does not pre-connect.
- **authentik** — forward-auth: `confs/` ships the nginx snippet; the Lua access handler whitelists outpost paths and forwards/extracts auth headers (needs enlarged proxy buffers for big JWTs).
- **discord / slack / webhook / matrix** — notifiers: build a JSON payload and POST it to an external URL from an `ngx.timer.at` async timer on the `log` hook (denials only), so request latency is unaffected. The generic case; little plugin-specific state.

## Pull requests & commits

- Default branch for PRs is `main`; active development lands on `dev` first.
- Commits follow conventional-commits style (`feat:`, `fix:`, `refactor:`, `ci/cd -`). See `git log` for prior examples.
- CONTRIBUTING.md requires an issue before non-trivial PRs.
