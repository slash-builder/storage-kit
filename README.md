# Storage Kit

> Content-addressed binary storage engine — format v2.
> The storage engine underneath [bitchain](https://github.com/slash-builder/bitchain).
> Published on crates.io as `slashbuilder-storage-kit`; the library is imported as `storage_kit`.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: pre-1.0, interface-locked](https://img.shields.io/badge/status-pre--1.0%20interface--locked-orange.svg)

Storage Kit is the SlashBuilder Kit ecosystem's content-addressed storage engine: **BLAKE3**
hashing, content-defined (FastCDC) or fixed-size chunking, **recursive
fragmentation** (fragment lists that themselves become content-addressed
objects once they exceed a size threshold, so multi-terabyte files don't
bloat a single reference list), **Zstd**-compressed packfiles on disk, and
**per-partition** isolation and dedup. It relocated here from
`slash-builder/bitchain` as a location fix, not a reimplementation — the
engine is unchanged, only where it lives.

`slash-builder/bitchain` is this crate's first consumer: it depends on
`storage-kit` for the engine and keeps only the CLI surface, its own
manifest format, and GC. **This crate does not depend on `bitchain`**, and
it deliberately owns no manifest type — `bitchain` and `bitchain-volume`
each keep their own distinct manifest shape over the same engine.

**v1 (SHA-256, the old `Store`/`Block`/`Manifest` scaffold) is gone.** This
crate implements format v2 only; a `--legacy` v1 read path, if one is ever
needed, is a `bitchain`-CLI-level concern, not this crate's.

## Status

Pre-1.0. The crate-root re-export block in `src/lib.rs` is the **frozen
public surface** (locked 2026-08-26) — see that file's doc comment for the
normative statement. `Context` and `Address` (`(hash, context)` addressing)
were retired in `0.2.0`; see `CHANGELOG.md`. Breaking the frozen surface
needs an explicit maintainer decision and a changelog entry, not a patch.

## Versions at a glance

The crate version (SemVer, in `Cargo.toml`) and the on-disk `FORMAT_VERSION`
are **independent numbers**. Pre-1.0, a breaking change bumps the crate's
*minor* version; 1.0 happens only when the API and its conformance tests are
frozen.

| Crate version | `FORMAT_VERSION` | What it is |
|---|---|---|
| `0.1.x` | 2 | The format-v2 engine (BLAKE3, FastCDC, Zstd packfiles, recursive fragmentation) |
| `0.2.0` | 3 | Format v3: `Context`/`Address` retired, `create`/`open` split, partition record |
| `0.2.1` | 3 | Adds the `ns` namespace layer (independent of the engine; format unchanged) |
| not yet released | 4 | Key-and-encryption seam (in design); would be `0.3.0` |

The minimum supported Rust version (MSRV) is **1.88**. Raising it is a
minor-version change, noted in the commit title, which release-plz turns into the `CHANGELOG.md` entry.

## Quick start

```toml
[dependencies]
slashbuilder-storage-kit = "0.2"
```

The package is `slashbuilder-storage-kit`; the library name is unchanged, so
you write `use storage_kit::...`. If you prefer the short name in
`Cargo.toml`, rename the dependency:
`storage-kit = { package = "slashbuilder-storage-kit", version = "0.2" }`.

```rust
use storage_kit::{
    EncryptionMode, ImmutableStore, PartitionId, PartitionSpec, PartitionStore, RetentionClass,
    Subject, SubjectKind,
};

// One partition per tenant — storage-kit never dedups across a partition
// boundary. `PartitionId::for_person` / `PartitionId::for_household` /
// `PartitionId::for_service` are the domain-separated constructors;
// `PartitionId::derive` is the general-purpose one. A partition is
// provisioned explicitly with `create` (its id must be derived from the
// subject you name); `open` is for a partition that already exists.
let partition_id = PartitionId::for_person("acct-123");
let spec = PartitionSpec {
    subject: Subject { kind: SubjectKind::Person, id: "acct-123".to_string() },
    retention_class: RetentionClass::Standard,
    encryption_mode: EncryptionMode::Plaintext,
    label: None,
};
let mut store = PartitionStore::create(store_root, partition_id, spec)?;

// Hashing is deterministic (BLAKE3) — the hash IS the block's identity,
// and a `put` for content already present in the partition is a no-op
// dedup hit, not a duplicate write.
let bytes = b"hello, world";
let hash = store.put(bytes)?;
println!("{hash}");

let back = store.get(&hash)?;   // verifies the BLAKE3 hash on every fetch
assert_eq!(&back[..], bytes);
```

Large content goes through recursive fragmentation rather than a single
`put`/`get` — see `storage_kit::build_fragment_tree` /
`storage_kit::read_fragment_tree`, re-exported at the crate root.

## Data model

```
Hash          — 32-byte BLAKE3 digest; sole key for physical block storage
                and within-partition dedup.
PartitionId   — 16-byte tenant-isolation id. Canonical construction is
                PartitionId::derive("<domain>:<id>"); for_person(account_id)
                and for_household(hid) are the standalone-first domain-
                separated convenience constructors (R3).
ChunkingProfile
              — how raw content is split: Fixed { block_size } or
                FastCdc { min_size, avg_size, max_size } (the default).
                Recorded so any implementation reconstructing the same
                bytes with the same profile reaches the same root hash.
FragmentTree  — result of fragmenting a byte slice: a root Hash plus a
                RootType (Leaf if the content fit in one chunk, List if
                there are one or more fold levels above the leaves).
```

The engine addresses by `(partition, hash)`. The earlier `Context` and
`Address` types (`(hash, context)` addressing) were retired in `0.2.0`;
logical identity belongs to the reference layer of the product above this
crate, not to the engine.

## Traits

```
ImmutableStore:                    # the four-method contract, frozen
  get(&hash) -> Vec<u8>            # verifies BLAKE3 on every read
  has(&hash) -> bool
  put(&[u8]) -> Hash               # dedups within the partition
  partition_id() -> PartitionId

MutableStore:                      # cache-state only — not used by the
  load(key) -> Vec<u8>             # bitchain protocol itself; manifests
  store(key, bytes)                # are immutable artifacts, no "advance
  cas(key, expected, new) -> bool  # the latest pointer" op
  list(prefix) -> Vec<String>

AsyncImmutableStore:                    # async counterpart to ImmutableStore,
  get(&hash) -> Result<Vec<u8>, _>      # for the backend transport layer
  put(&[u8]) -> Result<Hash, _>
  has(&hash) -> Result<bool, _>
  partition_id() -> PartitionId
```

Implementations that actually exist:

- **`PartitionStore`** — the reference `ImmutableStore`: packfile-backed
  local filesystem storage, one partition per directory, self-healing
  `.idx` rebuild from `.pack` files on open.
- **`LocalBackend`**, **`S3Backend`**, **`HttpBackend`** — async
  `AsyncImmutableStore` transport wrappers over the same content-addressed
  contract, for host applications that need non-blocking I/O.
  `S3Backend` targets S3 and S3-compatible object stores (MinIO, and — as
  of the `s3` feature landing — Wasabi/B2/R2); `HttpBackend` talks to a
  [Refraction](https://github.com/slash-builder/refraction) server.

`obliterate` and `copy_between_partitions` are **not** implemented —
`ImmutableStore` has the four methods above, not six. `MultiUriImmutableStore`
(try manifest URIs in order until one succeeds) is specified but unbuilt
and likely belongs in `bitchain`, since it needs a manifest to read URIs
from and this crate owns no manifest type.

## Cargo features

```toml
[dependencies]
slashbuilder-storage-kit = { version = "0.2", default-features = false, features = ["s3"] }
```

- `s3` (default-on) — pulls in `aws-sdk-s3`/`aws-config`/`bytes` and
  compiles `backend::S3Backend`.
- `http` (default-on) — pulls in `reqwest` and compiles
  `backend::HttpBackend`.
- `ns` (default-on) — the [namespace layer](#namespace-layer-ns), which adds
  `cap-std`, `cap-fs-ext` and `unicode-normalization` (plus `cap-primitives` on Windows).
- `conformance` — exposes `ns::conformance`, the suite a backend author runs.

`default = ["s3", "http", "ns"]`, so existing consumers see no change with no
action beyond the new `ns` module: 3 direct crates (`cap-std`, `cap-fs-ext`, `unicode-normalization`; 4 on Windows with `cap-primitives`) and about 11 added
packages in the lockfile, none of them network or async crates (opt out with `default-features = false`). A local-only consumer (no cloud transport, `PartitionStore` /
`LocalBackend` only) can build with `default-features = false` to link
neither cloud SDK. `LocalBackend` itself is always compiled — it has no
cloud dependency.

## Namespace layer (`ns`)

> **Status: new, and not frozen.** The engine's surface above is locked; the `ns` types and the `Backend` trait are not, and
> stay open until a read-only content-addressed backend has been written against the trait.

`storage_kit::ns` is a second, **independent** layer: one path-addressed file tree
(`/config/apps.toml`) over mounted backends, so a service stops hand-rolling
`O_NOFOLLOW` opens and `rename` dances. It shares no types or dependencies with the
content-addressed engine above (a test checks the source).

- **`Namespace`**: a mount table; longest prefix wins, mounts nest, mount ancestors are
  listed, a rename across mounts is `CrossMount`, and `ReadOnly` is enforced **per mount**: it
  refuses writes made through that mount, not writes to the same directory by another mount that
  overlaps it or by another process (see `ns::Namespace` for the overlap rules).
- **`HostDir`**: a mount over an OS directory, confined with `cap-std`: no `..`, no
  symlink or reparse point followed, only regular files and directories, `Replace` refuses
  a multiply-linked file (`Remove` and `RenameWithinMount` act on the name; no operation
  writes into an existing file; a *read* of a hard-linked file is served, and `stat` reports
  the link count), atomic `Replace` (temp file, fsync, rename, fsync dir).
  **Linux and macOS** are the targets; **Windows** compiles but is weaker and says so
  (`Caps::strict_confinement` is `false`; see `ns::hostdir` for the list).
- **`Memory`**: an in-memory mount with exact versions, for tests and scratch.
- **Five verbs**: `walk`, `read`, `stat`, `write` (a closed set of `WriteOp`s, not new
  verbs) and `watch` (a polling watcher in S0; batches carry `(epoch, generation)` so a
  gap *is* a rescan, and paths are namespace paths only).
- Every `read`/`stat` returns a `Version`; `write` takes `if_version`. Exact on `Memory`,
  **best effort on `HostDir`**, and `Caps` says which.
- Names follow one portable grammar (NFC only, no `..`, no Windows reserved names, no
  case-colliding siblings). Errors never contain a host path.
- Which host directories may be mounted, and by whom, is the **embedder's policy**: the
  Kit confines to the root it is given.

```rust
use std::sync::Arc;
use storage_kit::ns::{Access, HostDir, Namespace, NsPath, WriteOp};

let ns = Namespace::builder()
    .mount(NsPath::parse("/config")?, Arc::new(HostDir::open_ambient("/home/me/.config/app")?), Access::ReadWrite)
    .build()?;
let apps = NsPath::parse("/config/apps.toml")?;
let (bytes, version) = ns.read(&apps, 1 << 20)?;
ns.write(&apps, WriteOp::Replace, &bytes, Some(&version))?; // only if nobody changed it
```

It is pre-release surface, **not** part of the frozen engine surface, and S0 has no native
watcher, no content-addressed mount and no remote mount.

## Partitions and dedup

Every store is opened against exactly one `PartitionId`, and dedup is and
stays scoped to that single partition — no pack ever spans partitions.
Sharing content into a household is a **copy** written into the
household's own partition, not a cross-partition reference; callers wrap
that copy under a per-member household key above this crate, since this
crate has no key-wrapping concept.

`PartitionId::for_person(account_id)` / `PartitionId::for_household(hid)` /
`PartitionId::for_service(service_id)` are domain-separated convenience
constructors over `PartitionId::derive` — a person partition and a household
partition never collide even if `account_id` and `hid` happen to share a
string value.

## Hash invariant

A block's hash *is* its identity. `ImmutableStore`/`AsyncImmutableStore`
implementations verify the BLAKE3 hash of bytes returned from `get`
against the requested hash before returning. A mismatch is
`StorageError::HashMismatch { expected, actual }` and is treated as
storage corruption. Never compromise this invariant — it's the load-
bearing property of the whole system.

## Scope

**In scope.** BLAKE3 hashing, FastCDC-or-fixed chunking, Zstd-compressed
packfile storage, recursive fragmentation, partition isolation, the
`ImmutableStore`/`MutableStore` traits and `PartitionStore`, the async
`backend` layer (`LocalBackend`/`S3Backend`/`HttpBackend`), hash
verification on every fetch.

**Out of scope.** A CLI surface — that's the
[bitchain](https://github.com/slash-builder/bitchain) product. A server —
that's [Refraction](https://github.com/slash-builder/refraction). Any
manifest format — owned by each consuming product. Block availability
semantics for peer-to-peer or hub-mediated sharing — that is a concern of
the application layer above this crate.

## Building from source

```bash
git clone https://github.com/slash-builder/storage-kit.git
cd storage-kit
cargo build && cargo test
```

Rust 2021 edition; MSRV 1.88. Needs no private registry and no network
service: the tests use a temporary directory only.

## Contributing

Contributions welcome under Apache-2.0. Sign your commits with
`git commit -s` (Developer Certificate of Origin).

The frozen public surface (`src/lib.rs`'s root re-export block) is
conservative on purpose. A change to it needs an explicit maintainer
decision and a changelog entry, not a patch. See `CONTRIBUTING.md`.

## License

Apache-2.0 — see [LICENSE](LICENSE).

## About

Part of the **SlashBuilder Kit ecosystem**, at
[slash-builder](https://github.com/slash-builder). Storage Kit is the engine
underneath the `bitchain` CLI, `bitchain-volume` and Refraction.

Maintained by [SlashBuilder](https://slashbuilder.com) / Douglas Lockamy.
