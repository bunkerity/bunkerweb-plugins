# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

Official external plugins for [BunkerWeb](https://github.com/bunkerity/bunkerweb). Each top-level directory (`authentik/`, `clamav/`, `cloudflare/`, `coraza/`, `discord/`, `matrix/`, `slack/`, `virustotal/`, `webhook/`) is an independently-shipped plugin. There is no monorepo build — plugins are consumed by BunkerWeb at runtime by mounting the plugin directory into `/data/plugins` of the `bunkerweb-scheduler` container.

## Plugin anatomy

Every plugin follows the same BunkerWeb-imposed layout:

- `plugin.json` — id, name, version, `stream` (yes/no/partial), and the `settings` schema (each setting has `context` = `global`|`multisite`, `default`, `regex`, UI metadata). BunkerWeb reads this to register settings and render the UI.
- `<plugin>.lua` — main logic; requires `bunkerweb.plugin` and subclasses it via `middleclass`. Hook methods (`init_worker`, `access`, `log`, `preread`, etc.) return via `self:ret(ok, msg, [status])`. Runs inside OpenResty in the BunkerWeb nginx container.
- `ui/actions.py` — optional Python hooks for the BunkerWeb web UI. `pre_render(**kwargs)` returns card data; a function named after the plugin is called for the main page. `kwargs["bw_instances_utils"]` exposes BW helpers like `get_ping(service)`.
- `README.md` — user-facing docs; the settings table is generated from `plugin.json` via `.tests/misc/json2md.py` (run manually when settings change).
- `docs/diagram.mmd` — Mermaid architecture diagram shipped with each plugin and embedded inline as a ```mermaid block in its `README.md`(GitHub renders it natively). authentik is the reference style (subgraph + verdict diamond +`classDef ok/deny/svc/app`colors +`accTitle`/`accDescr`).

Coraza is special: it also ships `coraza/api/` — a standalone Go HTTP service (`main.go`, built by `coraza/api/Dockerfile`) that wraps `corazawaf/coraza/v3` and is called over HTTP by `coraza.lua`. Image is published as `bunkerity/bunkerweb-coraza`. CRS rules are vendored at build time by `crs.sh` (pinned to a commit hash, `.git` stripped).

## Versioning and compatibility

Release metadata lives in two places:

1. **Individual plugin version** in each `plugin.json` (currently `1.12`). Bump with `./misc/update_version.sh <new_version>` **run from the repo root** (it uses `find .` + `README.md` relative paths) — it rewrites every `plugin.json` **and the README badge** to that plugin version.
2. **Plugins-collection compatibility** in `COMPATIBILITY.json`. Historical entries used a separate version stream. Starting with `1.12`, add an entry matching the plugin release version and list only validated BunkerWeb versions (`1.6.14` for `1.12`). CI checks the entry for the actual manifest version, not the highest historical key.

`update_version.sh` only touches (1) and the README badges. When bumping: run the script for (1), and edit `COMPATIBILITY.json` by hand for (2). Preserve historical compatibility entries.

## Testing

Two layers: fast **unit tests** (no Docker) and **end-to-end integration tests** under `.tests/`.

### Unit tests (no Docker, run locally + in CI)

- **Go** — `coraza/api/main_test.go` covers the Go WAF service. Run `cd coraza/api && go mod tidy && go test -tags=coraza.rule.multiphase_evaluation ./...`. Both extras are required, not optional: `go.sum` is gitignored (the Dockerfile resolves deps at build time), so a bare `go test` fails with `missing go.sum entry`, and the build tag has to match the one the Dockerfile builds the binary with.
- **Python (pytest)** — `tests/test_ui_actions.py` parametrizes over every plugin's `ui/actions.py`; `tests/conftest.py` provides a `FakePingUtils` mock for `bw_instances_utils`. Run `pytest tests/ -q`.
- **Lua (busted)** — `spec/*_helpers_spec.lua` exercises the pure-logic helper modules (`authentik`, `clamav`, `discord`, `matrix`, `virustotal`) against `spec/helpers/fake_ngx.lua`. Run `busted`. This is why upstream-specific logic is factored into `<plugin>_helpers.lua` — so it's testable outside OpenResty.

### Integration tests (Docker, e2e)

- `./.tests/bw.sh <bw_tag>` pulls `bunkerity/bunkerweb:<tag>` + `bunkerweb-scheduler:<tag>` and retags them as `bunkerweb:tests` / `bunkerweb-scheduler:tests`. Must run first.
- Per-plugin scripts: `./.tests/clamav.sh`, `cloudflare.sh`, `coraza.sh`, `virustotal.sh`, `authentik.sh`, `sentinelone.sh`, `syswarden.sh`, and `notifier.sh` (the last covers discord/slack/webhook/matrix together in one multisite stack) — same list as the `integration` matrix in `.github/workflows/tests.yml`. Each copies the plugin into `/tmp/bunkerweb-plugins/<plugin>/bw-data/plugins` (owned `101:101`), copies `.tests/<plugin>/docker-compose.yml`, `sed`s it to the `:tests` tagged images, then `docker compose up --build -d` and polls with `curl`. EICAR file is downloaded for ClamAV. Most suites run against a mock upstream rather than the real service, so none of them needs a real vendor credential (VirusTotal passes `VIRUSTOTAL_API_KEY=dummy` and points `VIRUSTOTAL_API_URL` at `.tests/virustotal/vt-mock.conf`): see also `.tests/authentik/mock-outpost.conf`, `.tests/notifier/ratelimit.conf`, `.tests/cloudflare/cf-api-mock/`, `.tests/sentinelone/s1-mock.conf`, `.tests/syswarden/sw-mock/`.
- `.tests/utils.sh` provides `do_and_check_cmd` (runs a command, echoes output on failure, exits on non-zero) and `git_secure_clone` (pinned-commit clone helper). Source it with `. .tests/utils.sh`.
- Run a single plugin's e2e: `./.tests/bw.sh <bw_tag> && ./.tests/<plugin>.sh`. Pass `verbose` as `$1` to dump compose logs on success.
- **Resolve `<bw_tag>` the way CI does, every time — a stale local `bunkerweb:tests` hides real breakage.** `bw.sh` retags whatever it pulls, so an image left over from a previous session keeps passing while CI, which always resolves the _latest stable release_ at runtime, fails. That is exactly how the lua-resty-http `0.18.0` upgrade in BunkerWeb 1.6.14 (`0.17.2` up to 1.6.13) went unnoticed locally: it made `request_uri` reject a `POST` with a nil body, which broke `coraza.lua` on every bodyless request. Get the tag CI will use with `gh api repos/bunkerity/bunkerweb/releases/latest --jq .tag_name | sed 's/^v//'`.
- Tests need a working Docker daemon. `sudo` is used when available (to chown the mounted plugin to BW's uid 101) and every script falls back to `chmod -R a+rX` without it, so they run on a sudo-less workstation too. They leave state in `/tmp/bunkerweb-plugins/` — the scripts clean it at start, but `docker compose down -v` is the safe manual reset.

## CI/CD (`.github/workflows/tests.yml`)

Runs on push to `dev` and `main`. A `tag` job resolves the **latest stable BunkerWeb release** at runtime via the GitHub `releases/latest` API (`gh api repos/bunkerity/bunkerweb/releases/latest`, which excludes drafts and pre-releases; a leading `v` is stripped) and feeds that tag to every downstream job — same version on both branches, never pinned. Pipeline:

1. **plumber** — `.github/workflows/plumber.yml` (also runs weekly on a cron): [Plumber](https://getplumber.io) scans `.github/workflows/` for CI/CD supply-chain misconfigurations, gated at `min-score: B` with `soft-fail: false`. Policy overlay + rationale in `.github/plumber/` (read its README before touching a workflow — an unpinned action, a missing job `permissions:` block, or an event-supplied `ref:` will fail the run). The **`dev` and `main` branches must both stay protected**: `branchMustBeProtected` is Critical and caps the score at grade E.
2. **codeql** — `.github/workflows/codeql.yml` (also runs weekly on a cron), matrix `[python, go]`.
3. **lint** — `pre-commit run --all-files`.
4. **unit** — matrix `[go, python, lua]` (the unit tests above).
5. **integration** — `needs: [tag, lint, unit]`, matrix `plugin: [clamav, cloudflare, coraza, virustotal, authentik, notifier, sentinelone, syswarden]` — every per-plugin script above, none excluded; each runs `.tests/bw.sh <tag>` then `.tests/<plugin>.sh`.
6. **build-push** — `main` only, `needs: [plumber, tag, integration]` so a failing supply-chain scan blocks publishing: `./.tests/build-push.sh <tag>` builds and pushes the `bunkerweb-coraza` image.

There is **no pinned BW version** — the `tag` job always resolves the latest stable release, so the tests track upstream automatically. It then checks that all plugin versions agree and their `COMPATIBILITY.json` entry declares that BunkerWeb tag. The resolved tag flows into `bw.sh` (pulls `bunkerity/bunkerweb[-scheduler]:<tag>`) and, on `main`, into `build-push.sh` (which also tags the pushed `bunkerweb-coraza` image with it). The job fails fast if the API returns an empty or pre-release (hyphenated) tag.

Two tradeoffs of tracking upstream: (1) the `dev` branch no longer tests against BunkerWeb's `dev` build, so a plugin change that relies on an unreleased BW feature gets no CI coverage until BW ships a stable release; (2) every `main` push republishes `bunkerweb-coraza:latest` (and `:<stable>`) — harmless here because that image is a self-contained Go binary + vendored CRS, independent of the BW base tag, so only the extra tag's value moves.

## Releasing (`.github/workflows/release.yml`)

Releases are cut automatically from `main`. After `Tests` succeeds there, a `Release` workflow (a `workflow_run` trigger on the `Tests` workflow) reads the plugin version from `plugin.json` and, if no release `v<version>` exists yet (**drafts included** — it matches `tag_name` via `gh api`, since a draft has no git tag), opens a **draft** GitHub release with `softprops/action-gh-release` and auto-generated notes. A maintainer reviews and publishes it; a push that doesn't bump the version is a no-op. Two consequences of the `workflow_run` model: the file only fires once it is on the default branch (`main`), and it can't be tested from `dev`. So **cutting a release = `./misc/update_version.sh <ver>` → merge to `main` → publish the draft** the workflow creates.

## Linting — pre-commit is the source of truth

`.pre-commit-config.yaml` pins every linter to a frozen SHA. Install once with `pre-commit install`, then `pre-commit run --all-files` before committing. The stack:

- `black` (Python, py3.9) — configured in `pyproject.toml` with `line-length = 160`
- `flake8` — `--max-line-length=160 --ignore=E266,E402,E501,E722,W503` (E203 is **not** ignored, so let black's slice spacing decide: bind a complex slice bound to a name instead of writing `x[a : b - 1]`)
- `stylua` — config in `stylua.toml`
- `luacheck` — config in `.luacheckrc`, run with `--std min --codes --ranges --no-cache`
- `prettier`, `shellcheck`, `codespell`, `gitleaks`, standard pre-commit hygiene hooks

`coraza/api/coreruleset/**` and `LICENSE.md` are excluded from all hooks.

## Writing Lua plugin code — conventions to follow

- Always subclass via `local <name> = class("<name>", plugin)` and call `plugin.initialize(self, "<id>", ctx)` in `initialize(self, ctx)`.
- Every hook method returns `self:ret(ok_bool, msg, [http_status])`. To deny a request, return `self:ret(true, "reason", utils.get_deny_status())`.
- **Know which phase runs where — this is the single most expensive thing to get wrong.** `init()` runs in the master (`init_by_lua`), once per config load or reload, before the workers fork. `init_workers()` runs **in every worker**. `timer()` runs every 5s **in every worker**. `init_worker()` (singular) runs **exactly once per instance**: `confs/init-worker-lua.conf` gates it behind a `worker_lock` plus a shared `misc_ready` flag, so the first worker to take the lock runs every plugin's `init_worker()` and all the others return early — and a worker respawned after a crash finds the flag already set and never runs it at all. Verify against the shipped image (`docker run --rm --user 0 --entrypoint sh bunkerity/bunkerweb:<tag> -c 'cd /usr/share/bunkerweb && tar -cf - confs lua core' | tar -xf - -C <dir>`), never against memory and never against a local `bunkerweb` checkout — those track `dev` and differ from the tag CI actually runs.
- `init_worker` is therefore only for work that is _meant_ to run once per instance: a connectivity ping (`clamav`, `coraza`, `sentinelone`). Gate it with `utils.has_variable("USE_<PLUGIN>", "yes")` and skip when `self.is_loading` is true.
- **Per-worker state (compiled matchers, LRU caches, resolvers) must never be built in `init_worker`** — every other worker would be left empty and which worker answers a connection is an accept race. Build it in `init_workers()` (per worker; external plugins reach it — `helpers.order_plugins` appends any plugin declaring a phase, and core `metrics.lua` uses it for exactly this) **and** lazily on first use behind a module-level `*_built` flag, so a respawned worker and older BunkerWeb releases are still covered. `syswarden.lua` is the reference.
- A per-worker defect is invisible to a sequential test: under low load nginx keeps handing new connections to the same worker. Assert it with a **concurrent burst** (`.tests/syswarden.sh`, `.tests/cloudflare.sh`).
- `datastore:get/set(key, worker=true)` is **not** the shared dict — it is a per-Lua-VM `resty.lrucache`. It only works across workers because `init_by_lua` runs in the master and the VM is inherited by fork; a `set(..., true)` from a worker is invisible to every other worker.
- Use `ngx.socket` for TCP (see `clamav.lua` INSTREAM protocol) and `resty.http` for HTTP upstreams. Prefer `resty.upload` for streaming request bodies (`clamav.lua` is the reference).
- Cache scan results keyed by the file's hash so identical uploads skip the upstream. `clamav.lua` hashes the body with **SHA-512** (`resty.sha512`); `virustotal.lua` uses **SHA-256** (`resty.sha256`, matching VT's file-id) with a 24h TTL — it's the reference for cached HTTP-API lookups.
- **A cached verdict must carry the identity of the settings that produced it.** `cachestore:purge()` on reload is `mlcache:purge()` — it clears the instance-local cache and leaves every Redis key in place, so with `USE_REDIS=yes` a verdict survives the config change that should have invalidated it (new backend, new tenant, tightened thresholds) for the whole TTL. Hash those settings into the key: `clamav.lua`, `virustotal.lua` and `sentinelone.lua` each have a `cache_key()` doing exactly that.

## Writing scheduler jobs — the delivery contract

- Exit code is the whole API: `0` = success, no reload; `1` = success **and** reload nginx; `>=2` = failed (red in the UI). `plugin.json`'s `reload` key is validated and then never read (`JobScheduler.py:113,120`).
- **`1` is also the only thing that ships the cache.** `JobScheduler.run_pending()` POSTs `/var/cache/bunkerweb` to the instances only when some job in that batch exited `1` — the ship is welded to the reload. A job that writes a cache file and then exits `>=2` because a _later_ item failed leaves that file scheduler-side; the next run finds its hash unchanged, exits `0`, and it is **never delivered**. Any job whose cache is read by the Lua side must therefore carry a pending-delivery marker across runs: see `delivery_status()` in `cloudflare/jobs/cloudflare_helpers.py` and `syswarden/jobs/syswarden_helpers.py`, wired at the bottom of `cf-trusted-ips-download.py`, `cf-manage-origin-certs.py` and `syswarden-blocklist-download.py`.
- **`GET /bans` answers in two shapes, and the empty one carries no list.** `do_api_call` normalises the envelope in `api.lua` before it reaches the wire: one or more bans become `{"status":"success","msg":"success","data":[…]}`, none becomes `{"status":"success","msg":""}` with **no `data` key at all**. A job that treats a missing list as "I could not read the instance" then refuses to act at exactly the moment the last ban was lifted. `extract_instance_bans()` in `syswarden/jobs/syswarden_helpers.py` is the reference; it reads an empty `msg` on a `success` response as the empty list and everything else as unreadable.
- A job whose output is only read by the web UI needs no marker — `ui/actions.py` reads the job cache straight from the database (`db.get_job_cache_file(...)`), which is always current. `syswarden-telemetry-poll.py` is the reference.
- Validate everything before writing anything: prepare all outputs, bail on the first invalid one, then write. `syswarden-blocklist-download.py` does this; it is what keeps a half-updated pair of lists off the instances.

## Plugin-specific notes

The "Plugin anatomy" layout and the Lua conventions above are shared by all plugins. The non-obvious, per-plugin logic lives in code — these pointers save a re-read:

- **coraza** — the only plugin with an external sidecar. `coraza.lua` talks HTTP to the Go service in `coraza/api/` (`/ping` health check, `/request` for the verdict; the service returns deny/msg). CRS rules are vendored at build time by `coraza/api/crs.sh`, **pinned to a commit hash** with `.git` stripped; the two-stage `coraza/api/Dockerfile` builds the Go binary (multiphase-evaluation build tag) and bakes the rules in. Bumping CRS = bump the hash in `crs.sh`. Image: `bunkerity/bunkerweb-coraza`.
- **clamav** — speaks ClamAV's **binary INSTREAM protocol** over `ngx.socket.tcp` (each chunk framed by a 4-byte big-endian length, terminated by a zero-length frame), not HTTP. Streams the request body via `resty.upload`, scanning only multipart parts that have a real filename (`Content-Disposition` parsing handles quoted, unquoted, and RFC 5987 `filename*`). SHA-512 cache (see above).
- **virustotal** — HTTP to VT API v3 with `VIRUSTOTAL_API_KEY`; scans files and/or IPs. Verdict logic is in `virustotal_helpers.lua` (`evaluate()` compares VT's suspicious/malicious counts to configurable thresholds) — unit-tested in `spec/virustotal_helpers_spec.lua`. SHA-256 cache, 24h TTL. No usable ping endpoint, so `init_worker` does not pre-connect.
- **authentik** — forward-auth: `confs/` ships the nginx snippet; the Lua access handler whitelists outpost paths and forwards/extracts auth headers (needs enlarged proxy buffers for big JWTs).
- **discord / slack / webhook / matrix** — notifiers: build a JSON payload and POST it to an external URL from an `ngx.timer.at` async timer on the `log` hook (denials only), so request latency is unaffected. The generic case; little plugin-specific state.
- **cloudflare** — the only plugin with **scheduler `jobs`** (declared in `plugin.json` `"jobs"`, scripts under `cloudflare/jobs/`). Four jobs: `cf-trusted-ips-download` (downloads Cloudflare's public IP ranges → `set_real_ip_from`), `cf-manage-origin-certs` (manages Cloudflare Origin CA certs via the official `cloudflare` Python SDK — bundled in the scheduler image — and serves them through the `ssl_certificate` hook, storing parsed cert/key in `self.internalstore` like core letsencrypt), `cf-aop-ca-download` (Authenticated Origin Pulls CA), and `cf-edge-ban-sync` (pushes BunkerWeb bans to a Cloudflare account IP List, reads bans from Redis via `common_utils.get_redis_client`). `cloudflare.lua` denies non-Cloudflare peers (`access`/`preread`, fails **open** while the IP list is empty so it never denies everyone at boot), verifies Authenticated Origin Pulls (`$ssl_client_verify`), and strips spoofed `CF-*` headers. Pure logic is in `cloudflare_helpers.lua` (busted) + `cloudflare/jobs/cloudflare_helpers.py` (pytest). e2e (`.tests/cloudflare.sh`) mocks the Cloudflare IP-list + API (the dynamic `cf-api-mock` signs the submitted CSR) and drives deny/allow via **real container source IPs** on docker networks inside/outside a Cloudflare range (the deny check reads `realip_remote_addr`, the TCP peer — it can't be header-spoofed). Confs gate `real_ip_header` on `USE_REAL_IP != "yes"` and the AOP `ssl_verify_client` on `USE_MTLS != "yes"` to avoid duplicate-directive clashes with the core realip/mtls plugins. Settings/jobs support the Docker-secret `<NAME>_FILE` convention.
- **sentinelone** — inbound scanner built on the virustotal shape: HTTP to the SentinelOne API, verdict logic in `sentinelone_helpers.lua`, cache key namespaced by config identity (see above). `init_worker` pre-connects because the API has a usable health endpoint.
- **syswarden** — the only **bidirectional** plugin, and the most intricate. Three jobs: `syswarden-ban-push` (minute), `syswarden-blocklist-download` (hour), `syswarden-telemetry-poll` (minute). It speaks **two mutually exclusive HA dialects**, negotiated per peer from the capabilities the peer advertises: legacy `{"ips":[…]}` and provenance-aware `{"bans":[…]}`. Never mix them in one body — upstream answers `400 Ambiguous HA mutation`. **Ownership is the whole design.** `/ha/sync` writes into SysWarden's shared blocklist next to operator and real-HA-peer entries, so the plugin deletes only what it owns: an ownership registry in `pushed.json`, plus server-side provenance (`GET /ha/sync?details=true` returns each ban's `source`) on peers that track it. A provenance `DELETE` whose `source` does not match is a **silent no-op upstream** — `200 {"status":"ok"}`, nothing removed — which is safe here precisely because the delete set is derived from what the server itself attributed to `SYSWARDEN_BAN_SOURCE`. A claim is released only after an hour of continuous absence, and once a fence manifest is mounted (`SYSWARDEN_FENCE_MANIFEST`) only when **every** member proves a drained fence in the same pass. `syswarden_client.py` is the one job module that imports `requests` directly (the CI python job installs it for `tests/test_syswarden_client.py`). The TLS gate is CA bundle → fingerprint pin → refuse, with `SYSWARDEN_SSL_INSECURE=yes` as the only opt-out. `syswarden.lua` is the **reference for per-worker state** (`init_workers()` plus a lazy first-request build). Developed and verified against SysWarden **v4.03.3** on a real host; the v4.03.2 open-interval defect and the `peer_ips`/loopback traps are documented in `syswarden/README.md`. e2e `.tests/syswarden.sh` drives the dynamic `.tests/syswarden/sw-mock/`, which models both dialects, the fence, and the source-scoped delete.

## Pull requests & commits

- Default branch for PRs is `main`; active development lands on `dev` first.
- Commits follow conventional-commits style (`feat:`, `fix:`, `refactor:`, `ci/cd -`). See `git log` for prior examples.
- CONTRIBUTING.md requires an issue before non-trivial PRs.
