# Contributing to Storage Kit

Thanks for your interest. Contributions are welcome: bug reports, feature
requests, documentation improvements and code patches.

## Quick reference

| Item                 | Value                                                |
|----------------------|------------------------------------------------------|
| License              | Apache-2.0                                           |
| Sign-off             | `git commit -s` (Developer Certificate of Origin)    |
| Required approver    | A code owner, see [`.github/CODEOWNERS`](.github/CODEOWNERS) |
| CI                   | GitHub Actions, see [`.github/workflows/`](.github/workflows/) |
| Conduct              | [Contributor Covenant 2.1](CODE_OF_CONDUCT.md); reports go to `conduct@slashbuilder.com` |

## Before you start

Open an issue first for substantial design changes: new public API surfaces,
breaking changes, new dependencies. Small changes (typos, doc fixes, small bug
fixes) can go straight to a PR.

### Kit-specific invariants

**A block's hash IS its identity. Never compromise content-addressing.**

`ImmutableStore` and `AsyncImmutableStore` implementations must verify the
BLAKE3 hash of every fetch. A backend that returns bytes without checking they
hash to the requested value is broken, full stop.
`StorageError::HashMismatch { expected, actual }` is the canonical "this is
corrupt" signal.

**The frozen public surface is conservative on purpose.** The crate-root
re-export block in `src/lib.rs` is locked (see `CHANGELOG.md`, "Frozen"), and so
is the on-disk format version. A change to either needs an issue first, an
explicit maintainer decision and a changelog entry. `tests/conformance.rs` must
keep compiling against the crate-root re-exports alone.

## Local development

```sh
cargo build
cargo test
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --no-default-features      # local-only build: no S3 or HTTP backend
```

Requires Rust 1.88 or newer (the minimum supported version, checked in CI).
There is no private registry and no network service to set up: the tests use a
temporary directory only. Backends:

- **Local filesystem**: no system dependencies.
- **S3**: uses `aws-sdk-s3`; needs AWS or S3-compatible credentials at runtime.
  The test suite does not call a live endpoint.
- **HTTP**: talks to a Refraction server or any static host serving the same
  layout.

## Code style

- `cargo fmt --all` must produce no diff.
- `cargo clippy --all-targets --all-features -- -D warnings` must pass with zero
  warnings.

## Continuous integration

Every pull request runs formatting, clippy, docs, tests on Linux (x86-64 and
arm64), macOS and Windows, the minimum-supported-Rust check, `cargo-deny`
(advisories, licences, sources), a semver check against the latest published
version, a hygiene check, and a DCO check.

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes and sign off each commit with `git commit -s`.
3. Run the commands above and confirm they pass.
4. Open a pull request against `main` and address review feedback. A code owner
   (see [`.github/CODEOWNERS`](.github/CODEOWNERS)) must approve before merge.
5. The maintainer merges (squash by default).

## Sign your commits (DCO)

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
By adding a `Signed-off-by` line you certify that you wrote the change or have the right to submit it
under the project's licence (Apache-2.0).

```sh
git commit -s -m "your message"      # adds: Signed-off-by: Your Name <you@example.com>
git rebase --signoff main            # add the line to commits you already made
```

Use your real name and a working email address. A check on every pull request fails if any
non-merge commit is missing the line.

Under section 5 of the Apache License 2.0, a contribution you submit is licensed under the same
terms as the project unless you state otherwise. There is no separate contributor agreement.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be kind, assume good intent, and report problems to **conduct@slashbuilder.com**.

## About

Storage Kit is part of the **SlashBuilder Kit ecosystem**. It is the content-addressed storage engine
underneath the `bitchain` CLI. See the [README](README.md) for the project overview.
