# Repository Guidelines

## Project Structure & Module Organization

Each top-level directory containing `plugin.json` is an independently shipped BunkerWeb plugin. Keep metadata and settings in `plugin.json`, runtime hooks in `<plugin>.lua`, and pure Lua logic in `<plugin>_helpers.lua`. Plugins may also contain `ui/actions.py`, `jobs/`, `confs/`, and `docs/diagram.mmd`.

Shared Python tests live in `tests/`, Lua specs in `spec/`, and Coraza Go tests in `coraza/api/`. Docker integration fixtures and scripts live in `.tests/`; new-plugin scaffolding lives in `templates/`.

## Build, Test, and Development Commands

This repository has no monorepo build. Run commands from the repository root unless noted:

- `npm ci` installs the pinned Prettier version.
- `npm run format:check` checks supported text files; `pre-commit run --all-files` runs the full formatting, lint, spelling, and secret-scanning gate.
- `pytest tests/ -q` runs Python unit tests; `busted` runs Lua specs.
- From `coraza/api/`, run `go mod tidy`, then `go test -tags=coraza.rule.multiphase_evaluation ./...`.
- `bash .tests/bw.sh <stable-tag>` prepares BunkerWeb test images. Follow it with `bash .tests/<plugin>.sh` for the relevant Docker integration suite.

## Coding Style & Naming Conventions

Use four spaces and Black's 160-character limit for Python. Format Lua with StyLua and lint it with Luacheck. Prettier owns Markdown, JSON, YAML, and web assets. Use lowercase plugin IDs, `<plugin>.lua`, `<plugin>_helpers.lua`, and uppercase settings such as `USE_<PLUGIN>`. Update the plugin README and diagram when behavior or settings change.

## Testing Guidelines

Name Python files `test_*.py`, Lua specs `*_helpers_spec.lua`, and Go tests `*_test.go`. Add the smallest unit test that proves changed logic. Extend the matching `.tests/<plugin>.sh` flow when behavior depends on a running BunkerWeb stack. The project sets no coverage percentage, but changed behavior needs test coverage.

## Commit, Pull Request, and Security Guidelines

Recent history uses Conventional Commit subjects such as `feat(syswarden): ...`, `fix(tests): ...`, and `docs: ...`. Target `dev` for normal development; maintainers promote it to `main`. Link a non-trivial pull request to an issue, describe the behavior change, list verification commands, and update documentation. Report vulnerabilities privately through `SECURITY.md`; never commit API keys or credentials.

## Agent Workflow

Agents must prefix executed shell commands with `rtk`, inspect repository guidance before editing, and preserve unrelated changes. Do not commit, push, publish, or deploy without explicit authorization.
