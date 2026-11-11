# Releasing

Releases are automated with [release-plz](https://release-plz.dev). Publishing to crates.io, the `vX.Y.Z` git tag and the GitHub Release are all created by CI.

## How to release

1. Go to Actions → **Prepare Release** → **Run workflow** on `master`. release-plz opens (or updates) a pull request from a `release-plz-*` branch that bumps `version` in `Cargo.toml` and updates `CHANGELOG.md` with the commits since the last version published on crates.io.
2. Review the PR. To release a different version than the one proposed, change `version` in `Cargo.toml` and the matching heading in `CHANGELOG.md` on the PR branch (or run `release-plz set-version nmt-rs@X.Y.Z` locally and push). Pre-releases such as `0.3.0-rc.1` work the same way. Edit the changelog text freely.
3. Merge the PR. The **Publish Release** workflow waits for approval of the `release` environment. Once a maintainer approves, it publishes the crate, pushes the `vX.Y.Z` tag and creates the GitHub Release.

## Version bumps

release-plz picks the next version from the commits since the last release. Conventional-commit titles (`feat:`, `fix:`, `feat!:`) are used for this and for grouping the changelog; other titles land under "Other". Breaking API changes are also detected with `cargo-semver-checks`. On `0.x`, a breaking change bumps the minor version and anything else bumps the patch version.

## One-time setup

- **crates.io**: a token with the `publish-update` scope, limited to `nmt-rs` and created by a crate owner, stored as the `CARGO_REGISTRY_TOKEN` secret of the `release` environment. The token stops working if its creator stops being an owner, so the crate should have a GitHub team as owner (`cargo owner --add github:sovereign-labs:<team> nmt-rs`).
- **`release` environment**: required reviewers are the people allowed to publish. Don't restrict its deployment branches: on `pull_request` events the ref is `refs/pull/N/merge`, not `master`.
- **GitHub App**: needs Contents and Pull requests read/write permissions and must be installed on this repository. Store its client ID and private key as the repository secrets `RELEASE_APP_CLIENT_ID` and `RELEASE_APP_PRIVATE_KEY`. The app is used instead of `GITHUB_TOKEN` because pull requests opened with `GITHUB_TOKEN` don't trigger CI. If tags or `master` are protected by rulesets, allow the app to bypass them.
