//! Partition / packfile management — format v3.
//!
//! A `PartitionStore` owns exactly one partition's on-disk subtree:
//!
//! ```text
//! <store_root>/<partition_id_hex>/
//!   active/active.pack        — currently-open, appendable pack (no trailer)
//!   packs/<xx>/<pack_id>.pack — sealed, immutable, content-addressed packs
//!   packs/<xx>/<pack_id>.idx  — derived index, rebuildable, never authoritative
//!   manifests/*.json          — manifests ingested into this partition
//! ```
//!
//! No pack file, and no `PartitionStore`, ever spans more than one
//! partition — that's the physical boundary the whole GC and dedup story
//! relies on.

pub mod packfile;

use crate::addressing::{Hash, PartitionId};
use crate::error::{Result, StorageError};
use crate::partition::{self, EncryptionMode, PartitionRecord, PartitionSpec, RetentionClass};
use packfile::PackWriter;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Soft cap: an active pack is sealed once it reaches this size.
pub const SEAL_CAP_BYTES: u64 = 128 * 1024 * 1024;

/// Enumerate every **provisioned** partition under `store_root` — one with
/// a `partition.json` record, not merely a 32-hex-char directory. Used by
/// CLI commands (`ls`, `gc`, `push`) that operate "over every partition"
/// when the caller doesn't name one explicitly.
///
/// Spec §3.7 rule 4: mkdir-on-first-write ended with the `create`/`open`
/// split, so a bare directory with no record is an orphan, not a
/// partition — `list_partitions` never reports one.
pub fn list_partitions(store_root: &Path) -> Result<Vec<PartitionId>> {
    if !store_root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(store_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.len() == 32 && name.chars().all(|c| c.is_ascii_hexdigit()) {
            let partition_id = PartitionId::from_hex(name)?;
            if partition::is_provisioned(store_root, partition_id) {
                out.push(partition_id);
            }
        }
    }
    out.sort_by_key(|p| p.to_hex());
    Ok(out)
}

/// The full content-addressed storage contract a backend must satisfy:
/// partition-scoped, immutable once written, hash-verified on every read.
///
/// Naming reconciliation (the design review, 2026-08-23): the 2026-06
/// storage-alignment lock specified `ImmutableStore`/`MutableStore` as the
/// trait vocabulary; the shipped v2 code (pre-relocation) split this same
/// contract into `ReadBlock`/`WriteBlock` sub-traits plus a composed
/// `ImmutableStore` marker. This trait collapses that split — same four
/// methods, same signatures, same implementors — under the single locked
/// name. No behavior changed by the collapse.
pub trait ImmutableStore {
    /// Fetch and verify content by hash.
    fn get(&self, hash: &Hash) -> Result<Vec<u8>>;
    fn has(&self, hash: &Hash) -> bool;
    /// Store `data`, returning its content hash. A `put` for content already
    /// present in this partition is a no-op dedup hit, not a duplicate
    /// write.
    fn put(&mut self, data: &[u8]) -> Result<Hash>;
    fn partition_id(&self) -> PartitionId;
}

/// Cache-state store for the bitchain *protocol* layer (e.g. a "latest"
/// pointer keyed by name) — distinct from [`ImmutableStore`], which has no
/// notion of a mutable pointer: every address it serves is a stable content
/// hash. Declared per the 2026-06 lock's target trait shape so the
/// vocabulary exists; no implementation ships with this relocation
/// — bitchain's manifest protocol treats manifests as immutable,
/// content-addressed artifacts and has no current caller for this trait.
pub trait MutableStore {
    fn load(&self, key: &str) -> Result<Vec<u8>>;
    fn store(&mut self, key: &str, data: &[u8]) -> Result<()>;
    /// Compare-and-swap: succeeds (returns `Ok(true)`) only if the value
    /// currently stored at `key` equals `expected` (`None` means "key must
    /// not exist yet").
    fn cas(&mut self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool>;
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

struct SealedPack {
    pack_id: Hash,
    path: PathBuf,
    /// hash -> (byte offset, full entry meta) within this pack. Carries the
    /// full record, not merely the offset, so a meta-preserving copy (GC's
    /// repack) can read an entry's meta straight from the loaded index
    /// without touching the pack at all.
    offsets: HashMap<Hash, (u64, packfile::EntryMeta)>,
}

/// The reference `ImmutableStore` implementation: a single partition's
/// packfiles on the local filesystem.
pub struct PartitionStore {
    root: PathBuf,
    partition_id: PartitionId,
    record: PartitionRecord,
    active: PackWriter,
    sealed: Vec<SealedPack>,
    /// hash -> index into `sealed`, for O(1) dispatch on read.
    sealed_lookup: HashMap<Hash, usize>,
}

impl PartitionStore {
    /// Provision a new partition (spec §3.7). Fails with
    /// [`StorageError::PartitionAlreadyProvisioned`] if `partition.json`
    /// already exists. **The only place a partition directory is ever
    /// created** — `open` creates none.
    ///
    /// Verifies `PartitionId::derive("{subject.kind}:{subject.id}") ==
    /// partition_id`: a partition cannot be provisioned under a subject it
    /// was not derived from. Writes the portable record
    /// (`partition.json`, inside the partition directory, replicated) and
    /// the local subject binding (`partitions.local.json`, at the store
    /// root, never replicated) as two separate writes — see
    /// [`crate::partition`] for why they are split.
    ///
    /// There is no default retention class: `spec.retention_class` is a
    /// required field, and this method never substitutes one.
    pub fn create(
        store_root: &Path,
        partition_id: PartitionId,
        spec: PartitionSpec,
    ) -> Result<Self> {
        partition::verify_derivation(partition_id, &spec.subject)?;

        if partition::is_provisioned(store_root, partition_id) {
            return Err(StorageError::PartitionAlreadyProvisioned(
                partition_id.to_hex(),
            ));
        }

        let root = store_root.join(partition_id.to_hex());
        fs::create_dir_all(&root)?;

        let record =
            partition::new_record(partition_id, spec.retention_class, spec.encryption_mode);
        partition::write_new_record(store_root, partition_id, &record)?;
        partition::bind_local(store_root, partition_id, &spec.subject, &spec.label)?;

        Self::open_provisioned(store_root, partition_id, record)
    }

    /// Open an already-provisioned partition (spec §3.7). Fails with
    /// [`StorageError::PartitionNotProvisioned`] if `partition.json` is
    /// absent — there is no default retention class or fallback
    /// behaviour, because defaulting here would be exactly the "decide
    /// retention at ingest, not retrofit it" rule the record exists to
    /// enforce. Creates no directories. Rebuilds/self-heals any missing
    /// `.idx` files from their `.pack` counterparts — the index is
    /// derived, never trusted blindly.
    ///
    /// Does **not** require `partitions.local.json` to have an entry for
    /// this partition — a replica has no local binding and is still
    /// readable.
    pub fn open(store_root: &Path, partition_id: PartitionId) -> Result<Self> {
        if !partition::is_provisioned(store_root, partition_id) {
            return Err(StorageError::PartitionNotProvisioned(partition_id.to_hex()));
        }
        let record = partition::load_record(store_root, partition_id)?;
        Self::open_provisioned(store_root, partition_id, record)
    }

    /// Shared mechanics for `create`/`open` once `partition.json` is known
    /// to exist and has been loaded: scan sealed packs, open the active
    /// pack. Both callers have already established provisioning; this
    /// step performs no provisioning decisions of its own.
    fn open_provisioned(
        store_root: &Path,
        partition_id: PartitionId,
        record: PartitionRecord,
    ) -> Result<Self> {
        let root = store_root.join(partition_id.to_hex());
        let packs_dir = root.join("packs");
        let active_path = root.join("active").join("active.pack");
        fs::create_dir_all(&packs_dir)?;

        let active = PackWriter::open_active(&active_path, partition_id)?;

        let mut sealed = Vec::new();
        let mut sealed_lookup = HashMap::new();
        if packs_dir.exists() {
            for shard_entry in fs::read_dir(&packs_dir)? {
                let shard_entry = shard_entry?;
                if !shard_entry.file_type()?.is_dir() {
                    continue;
                }
                for pack_entry in fs::read_dir(shard_entry.path())? {
                    let pack_entry = pack_entry?;
                    let path = pack_entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("pack") {
                        continue;
                    }
                    let pack_id_hex = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| StorageError::CorruptPack("bad pack filename".into()))?
                        .to_string();
                    let pack_id = Hash::from_hex(&pack_id_hex)?;

                    let idx_path = path.with_extension("idx");
                    let offsets = match packfile::read_index(&idx_path) {
                        Ok(idx) => idx,
                        Err(_) => {
                            // Self-heal: rebuild from the pack and persist.
                            let entries = packfile::rebuild_index_entries(&path)?;
                            packfile::write_index(&idx_path, &partition_id, &entries)?;
                            entries
                                .into_iter()
                                .map(|(off, m)| (m.hash, (off, m)))
                                .collect()
                        }
                    };

                    let idx = sealed.len();
                    for hash in offsets.keys() {
                        sealed_lookup.insert(*hash, idx);
                    }
                    sealed.push(SealedPack {
                        pack_id,
                        path,
                        offsets,
                    });
                }
            }
        }

        Ok(PartitionStore {
            root,
            partition_id,
            record,
            active,
            sealed,
            sealed_lookup,
        })
    }

    pub fn partition_root(&self) -> &Path {
        &self.root
    }

    /// The portable partition record this store was opened with.
    /// Deliberately carries no [`crate::partition::Subject`] — see
    /// [`crate::partition`]'s module docs for why that omission is the
    /// guarantee, not an oversight.
    pub fn record(&self) -> &PartitionRecord {
        &self.record
    }

    /// This partition's retention class. Immutable for the partition's
    /// lifetime — there is no `set_retention_class`; no transition is
    /// legal in either direction. Minting a new partition and copying into
    /// it is the only way to change one.
    pub fn retention_class(&self) -> RetentionClass {
        self.record.retention_class
    }

    /// This partition's encryption mode. Immutable for the partition's
    /// lifetime — there is no `set_encryption_mode`; no transition is legal
    /// in either direction. Minting a new partition and copying into it is
    /// the only way to change one. This crate implements no encryption
    /// today; `plaintext` is the only value any current caller can produce.
    pub fn encryption_mode(&self) -> EncryptionMode {
        self.record.encryption_mode
    }

    pub fn packs_dir(&self) -> PathBuf {
        self.root.join("packs")
    }

    pub fn manifests_dir(&self) -> PathBuf {
        self.root.join("manifests")
    }

    /// Persist `manifest_json` under this partition's `manifests/` tree so
    /// `gc` can discover it as a root to keep alive.
    pub fn write_manifest(&self, name: &str, manifest_json: &str) -> Result<PathBuf> {
        let dir = self.manifests_dir();
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{name}.json"));
        fs::write(&path, manifest_json)?;
        Ok(path)
    }

    pub fn list_manifests(&self) -> Result<Vec<PathBuf>> {
        let dir = self.manifests_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|e| e.to_str()) == Some("json") {
                out.push(entry.path());
            }
        }
        out.sort();
        Ok(out)
    }

    /// List every entry hash currently reachable in this partition — both
    /// sealed packs and the active pack.
    pub fn all_hashes(&self) -> Vec<Hash> {
        let mut out: Vec<Hash> = self.active.offsets.keys().copied().collect();
        for pack in &self.sealed {
            out.extend(pack.offsets.keys().copied());
        }
        out
    }

    pub fn sealed_pack_ids(&self) -> Vec<Hash> {
        self.sealed.iter().map(|p| p.pack_id).collect()
    }

    /// Number of entries written into the still-open active pack (not yet
    /// sealed into an immutable `.pack`). Exposed for `ls` summaries.
    pub fn active_entry_count(&self) -> u64 {
        self.active.entry_count
    }

    /// Verify every sealed pack's trailer + every entry's hash across the
    /// whole partition (sealed and active). Returns the number of entries
    /// checked.
    pub fn verify_all(&self) -> Result<u64> {
        let mut checked = 0u64;
        for pack in &self.sealed {
            packfile::verify_trailer(&pack.path)?;
            for (offset, _meta) in pack.offsets.values() {
                packfile::get_at(&pack.path, *offset)?;
                checked += 1;
            }
        }
        // Active pack has no trailer yet; verify each entry by hash.
        for hash in self.active.offsets.keys() {
            self.get(hash)?;
            checked += 1;
        }
        Ok(checked)
    }

    fn seal_active_if_over_cap(&mut self) -> Result<()> {
        if self.active.len < SEAL_CAP_BYTES {
            return Ok(());
        }
        let fresh_active_path = self.root.join("active").join("active.pack");
        let old = std::mem::replace(
            &mut self.active,
            // Placeholder; immediately overwritten below. `open_active` on
            // a not-yet-existing path is cheap (just a header write).
            PackWriter::open_active(
                &fresh_active_path.with_extension("pack.next"),
                self.partition_id,
            )?,
        );
        let (pack_id, path) = old.seal(&self.packs_dir())?;
        let offsets = packfile::read_index(&path.with_extension("idx"))?;
        let idx = self.sealed.len();
        for hash in offsets.keys() {
            self.sealed_lookup.insert(*hash, idx);
        }
        self.sealed.push(SealedPack {
            pack_id,
            path,
            offsets,
        });
        // Replace the throwaway placeholder with the real fresh active pack.
        let _ = fs::remove_file(fresh_active_path.with_extension("pack.next"));
        self.active = PackWriter::open_active(&fresh_active_path, self.partition_id)?;
        Ok(())
    }

    /// Force-seal the current active pack even if it hasn't hit the soft
    /// cap. Used by `gc` (which needs a clean set of sealed packs to
    /// rewrite) and is otherwise optional — the 128 MiB cap is the normal
    /// trigger.
    pub fn seal_active(&mut self) -> Result<Option<Hash>> {
        if self.active.entry_count == 0 {
            return Ok(None);
        }
        let fresh_active_path = self.root.join("active").join("active.pack");
        let old = std::mem::replace(
            &mut self.active,
            PackWriter::open_active(
                &fresh_active_path.with_extension("pack.sealing"),
                self.partition_id,
            )?,
        );
        let (pack_id, path) = old.seal(&self.packs_dir())?;
        let offsets = packfile::read_index(&path.with_extension("idx"))?;
        let idx = self.sealed.len();
        for hash in offsets.keys() {
            self.sealed_lookup.insert(*hash, idx);
        }
        self.sealed.push(SealedPack {
            pack_id,
            path,
            offsets,
        });
        let _ = fs::remove_file(fresh_active_path.with_extension("pack.sealing"));
        self.active = PackWriter::open_active(&fresh_active_path, self.partition_id)?;
        Ok(Some(pack_id))
    }
}

impl PartitionStore {
    /// Fetch `(meta, payload)` for `hash` **without** decoding, hash-
    /// verifying, or validating reserved fields — the raw, byte-exact form
    /// a meta-preserving copy (GC's repack) needs so it can relocate an
    /// entry without interpreting what it means. Contrast
    /// [`ImmutableStore::get`], which is the validated, decoded, verified
    /// form real content reads go through. Additive: not part of the
    /// frozen `ImmutableStore` trait.
    pub fn get_raw(&self, hash: &Hash) -> Result<(packfile::EntryMeta, Vec<u8>)> {
        if let Some(offset) = self.active.offsets.get(hash) {
            return self.active.read_payload_at(*offset);
        }
        if let Some(&idx) = self.sealed_lookup.get(hash) {
            let pack = &self.sealed[idx];
            let (offset, _meta) = *pack.offsets.get(hash).ok_or_else(|| {
                StorageError::NotFound(format!("{hash} indexed but missing in pack"))
            })?;
            return packfile::get_raw_at(&pack.path, offset);
        }
        Err(StorageError::NotFound(hash.to_hex()))
    }

    /// Append `payload` verbatim under `meta` — the byte-exact primitive a
    /// meta-preserving copy (GC's repack) needs, bypassing the normal
    /// encode path. `meta.hash` is trusted as-is: the caller is relocating
    /// an already-hashed entry forward, not producing new content. Still
    /// dedups against what this partition already holds. Additive: not
    /// part of the frozen `ImmutableStore` trait, and carries no validation
    /// — see [`packfile::EntryMeta::validate_reserved`]'s module docs for
    /// why a byte-mover is deliberately meta-blind.
    pub fn put_raw(&mut self, meta: packfile::EntryMeta, payload: &[u8]) -> Result<Hash> {
        if self.has(&meta.hash) {
            return Ok(meta.hash); // per-partition dedup, keyed by hash only
        }
        self.active.append_raw(&meta, payload)?;
        self.seal_active_if_over_cap()?;
        Ok(meta.hash)
    }
}

impl ImmutableStore for PartitionStore {
    fn get(&self, hash: &Hash) -> Result<Vec<u8>> {
        if let Some(offset) = self.active.offsets.get(hash) {
            let (meta, payload) = self.active.read_payload_at(*offset)?;
            meta.validate_reserved()?;
            let decoded = packfile::decode(meta.codec, &payload)?;
            let actual = Hash::of(&decoded);
            if actual != *hash {
                return Err(StorageError::HashMismatch {
                    expected: hash.to_hex(),
                    actual: actual.to_hex(),
                });
            }
            return Ok(decoded);
        }
        if let Some(&idx) = self.sealed_lookup.get(hash) {
            let pack = &self.sealed[idx];
            let (offset, _meta) = *pack.offsets.get(hash).ok_or_else(|| {
                StorageError::NotFound(format!("{hash} indexed but missing in pack"))
            })?;
            return packfile::get_at(&pack.path, offset);
        }
        Err(StorageError::NotFound(hash.to_hex()))
    }

    fn has(&self, hash: &Hash) -> bool {
        self.active.offsets.contains_key(hash) || self.sealed_lookup.contains_key(hash)
    }

    fn put(&mut self, data: &[u8]) -> Result<Hash> {
        let hash = Hash::of(data);
        if self.has(&hash) {
            return Ok(hash); // per-partition dedup, keyed by hash only
        }
        let (codec, payload) = packfile::encode(data)?;
        self.active
            .append(hash, codec, data.len() as u64, &payload)?;
        self.seal_active_if_over_cap()?;
        Ok(hash)
    }

    fn partition_id(&self) -> PartitionId {
        self.partition_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition::{Subject, SubjectKind};
    use tempfile::tempdir;

    /// Provision a person partition for `name` with `retention_class`,
    /// via the real `create()` path — mkdir-on-first-write ended, so every
    /// test that wants a working store must provision one explicitly now.
    fn create_person(dir: &Path, name: &str, retention_class: RetentionClass) -> PartitionStore {
        let partition_id = PartitionId::for_person(name);
        let spec = PartitionSpec {
            subject: Subject {
                kind: SubjectKind::Person,
                id: name.to_string(),
            },
            retention_class,
            encryption_mode: EncryptionMode::Plaintext,
            label: None,
        };
        PartitionStore::create(dir, partition_id, spec).unwrap()
    }

    #[test]
    fn put_dedups_within_partition() {
        let dir = tempdir().unwrap();
        let mut store = create_person(dir.path(), "dedup-test", RetentionClass::Standard);

        let h1 = store.put(b"same bytes").unwrap();
        let h2 = store.put(b"same bytes").unwrap();
        assert_eq!(h1, h2);
        assert_eq!(
            store.active.entry_count, 1,
            "second put must be a dedup no-op"
        );
    }

    #[test]
    fn put_then_get_roundtrips() {
        let dir = tempdir().unwrap();
        let mut store = create_person(dir.path(), "roundtrip-test", RetentionClass::Standard);
        let hash = store.put(b"round trip me").unwrap();
        let back = store.get(&hash).unwrap();
        assert_eq!(back, b"round trip me");
    }

    #[test]
    fn seal_then_reopen_still_reads() {
        let dir = tempdir().unwrap();
        let partition_id = PartitionId::for_person("seal-reopen-test");
        let hash;
        {
            let mut store = create_person(dir.path(), "seal-reopen-test", RetentionClass::Standard);
            hash = store.put(b"persist across reopen").unwrap();
            store.seal_active().unwrap();
        }
        let store2 = PartitionStore::open(dir.path(), partition_id).unwrap();
        let back = store2.get(&hash).unwrap();
        assert_eq!(back, b"persist across reopen");
    }

    #[test]
    fn partitions_are_isolated_directories() {
        let dir = tempdir().unwrap();
        let mut store_a = create_person(dir.path(), "partition-a", RetentionClass::Standard);
        let mut store_b = create_person(dir.path(), "partition-b", RetentionClass::Standard);

        let hash_a = store_a.put(b"only in a").unwrap();
        let _hash_b = store_b.put(b"only in b").unwrap();

        assert!(store_a.has(&hash_a));
        assert!(!store_b.has(&hash_a));
        assert_ne!(store_a.partition_root(), store_b.partition_root());
    }

    #[test]
    fn open_on_an_unprovisioned_partition_fails() {
        let dir = tempdir().unwrap();
        let partition_id = PartitionId::for_person("never-created");
        let err = match PartitionStore::open(dir.path(), partition_id) {
            Err(e) => e,
            Ok(_) => panic!("open() must not create a partition on first use"),
        };
        assert!(matches!(err, StorageError::PartitionNotProvisioned(_)));
    }

    #[test]
    fn open_creates_no_directory() {
        let dir = tempdir().unwrap();
        let partition_id = PartitionId::for_person("open-creates-nothing");
        let _ = PartitionStore::open(dir.path(), partition_id);
        assert!(
            !dir.path().join(partition_id.to_hex()).exists(),
            "open() on an unprovisioned partition must create no directory"
        );
    }

    #[test]
    fn create_twice_fails_already_provisioned() {
        let dir = tempdir().unwrap();
        let partition_id = PartitionId::for_person("double-create");
        let spec = || PartitionSpec {
            subject: Subject {
                kind: SubjectKind::Person,
                id: "double-create".to_string(),
            },
            retention_class: RetentionClass::Standard,
            encryption_mode: EncryptionMode::Plaintext,
            label: None,
        };
        PartitionStore::create(dir.path(), partition_id, spec()).unwrap();
        let err = match PartitionStore::create(dir.path(), partition_id, spec()) {
            Err(e) => e,
            Ok(_) => panic!("re-provisioning the same partition must fail"),
        };
        assert!(matches!(err, StorageError::PartitionAlreadyProvisioned(_)));
    }

    #[test]
    fn create_rejects_a_subject_that_does_not_derive_the_partition_id() {
        let dir = tempdir().unwrap();
        // Deliberately mismatched: this id was not derived from the subject.
        let partition_id = PartitionId::for_person("someone-else");
        let spec = PartitionSpec {
            subject: Subject {
                kind: SubjectKind::Person,
                id: "not-someone-else".to_string(),
            },
            retention_class: RetentionClass::Standard,
            encryption_mode: EncryptionMode::Plaintext,
            label: None,
        };
        let err = match PartitionStore::create(dir.path(), partition_id, spec) {
            Err(e) => e,
            Ok(_) => panic!(
                "a partition must not be provisionable under a subject it wasn't derived from"
            ),
        };
        assert!(matches!(err, StorageError::PartitionBoundary(_)));
    }

    #[test]
    fn list_partitions_only_reports_provisioned_partitions() {
        let dir = tempdir().unwrap();
        let provisioned = create_person(dir.path(), "listed", RetentionClass::Standard);
        let provisioned_id = provisioned.partition_id();

        // An orphan: a 32-hex directory with no partition.json.
        let orphan_id = PartitionId::for_person("orphan");
        fs::create_dir_all(dir.path().join(orphan_id.to_hex())).unwrap();

        let listed = list_partitions(dir.path()).unwrap();
        assert!(listed.contains(&provisioned_id));
        assert!(
            !listed.contains(&orphan_id),
            "a directory with no partition.json must not be reported as a partition"
        );
    }

    #[test]
    fn retention_class_is_visible_and_matches_what_was_provisioned() {
        let dir = tempdir().unwrap();
        let store = create_person(dir.path(), "durable-check", RetentionClass::Durable);
        assert_eq!(store.retention_class(), RetentionClass::Durable);
    }

    #[test]
    fn encryption_mode_is_visible_and_matches_what_was_provisioned() {
        let dir = tempdir().unwrap();
        let partition_id = PartitionId::for_person("sealed-required-check");
        let spec = PartitionSpec {
            subject: Subject {
                kind: SubjectKind::Person,
                id: "sealed-required-check".to_string(),
            },
            retention_class: RetentionClass::Standard,
            encryption_mode: EncryptionMode::SealedRequired,
            label: None,
        };
        let store = PartitionStore::create(dir.path(), partition_id, spec).unwrap();
        assert_eq!(store.encryption_mode(), EncryptionMode::SealedRequired);

        // Immutable across a reopen, same as retention_class.
        let reopened = PartitionStore::open(dir.path(), partition_id).unwrap();
        assert_eq!(reopened.encryption_mode(), EncryptionMode::SealedRequired);
    }

    #[test]
    fn encryption_mode_defaults_to_plaintext_for_current_callers() {
        // `create_person` is the standard test helper; it must produce the
        // only value any current caller can produce — there is no
        // encryption implemented yet.
        let dir = tempdir().unwrap();
        let store = create_person(dir.path(), "plaintext-check", RetentionClass::Standard);
        assert_eq!(store.encryption_mode(), EncryptionMode::Plaintext);
    }
}
