# Plumber

CI/CD security scanning for the GitHub Actions workflows in this repository.
[Plumber](https://getplumber.io) statically analyses `.github/workflows/` for
supply-chain and pipeline misconfigurations: unpinned or unvetted actions,
`secrets: inherit`, missing `permissions:` blocks, dangerous triggers,
template injection, cache poisoning and branch protection gaps.

It complements the existing CodeQL workflow (which analyses the Python and Go
source, not the pipeline); the two do not overlap.

## Files

| Path                            | Purpose                                    |
| ------------------------------- | ------------------------------------------ |
| `.github/plumber/plumber.yaml`  | Policy overlay on top of `plumber:default` |
| `.github/plumber/README.md`     | This file                                  |
| `.github/workflows/plumber.yml` | Reusable workflow invoked by `tests.yml`   |

## Running it locally

```bash
brew install getplumber/tap/plumber   # or grab the binary from the GitHub releases
plumber analyze --config .github/plumber/plumber.yaml --score
plumber explain ISSUE-801             # details for a given issue code
```

`plumber analyze` scans the local workflows and queries the GitHub API for
branch protection. That last control needs a token with `Administration: read`;
without it, protection findings are incomplete rather than wrong.

## Policy

`plumber.yaml` extends `plumber:default` and only adds an allowlist of the
third-party actions this repository already relies on — here a single one,
`softprops/action-gh-release`, used by `release.yml`. The entry names an exact
`owner/repo` rather than an owner wildcard, so trust cannot spread to other or
future repositories under that account. Every action in this repo is pinned by
commit SHA.

`branchMustBeProtected` is left at its default, which requires protection on
both `main` and `dev`. An unprotected branch is a Critical finding and caps the
score at 30 points (grade E), so both branches must stay protected for CI to
pass.

## Gating

`tests.yml` invokes Plumber on every push to `dev` and `main`, and the reusable
workflow also runs weekly on its own schedule. It is gated at `min-score: B`
with `soft-fail: false`, so scores of C, D or E fail the run — and `build-push`
lists `plumber` in its `needs`, so a repository that fails its own supply-chain
scan never pushes an image. Results land in the Code Scanning tab.

Every input is set explicitly in `plumber.yml`, including those that match the
action's own defaults, so that an auditor reads the effective configuration
from the workflow alone and never has to diff it against `action.yml` at some
past tag. `verify-attestation: true` keeps the sigstore/SLSA provenance check
on the downloaded binary; `score-push: true` publishes the score behind the
badge in the root `README.md`.

Each run also uploads a `plumber-report` artifact holding the JSON report, the
PBOM, the CycloneDX SBOM and the raw SARIF (`upload-artifacts: true`). The
SARIF is redundant with Code Scanning; the PBOM and SBOM are kept as per-run
evidence of what the pipeline consumed.
