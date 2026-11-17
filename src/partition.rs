//! The partition metadata record and provisioning API — format v3.
//!
//! Implements the "partition record and provisioning" sections of
//! the design spec (the format-reservations spec,
//! §3, §4). Deliberately scoped to **exactly** that: this module does not
//! touch the pack/idx entry layout (§1, §2) and does not add `context` or
//! `key_epoch` fields to any packed byte — those stay gated on the open
//! `(hash, context)` ruling and land in a later change.
//!
//! Two files, at two different levels, because two different things are
//! recorded and only one of them should ever leave the machine:
//!
//! ```text
//! <store_root>/
//!   partitions.local.json          — LOCAL subject bindings, store-level.
//!                                    NEVER replicated. NEVER inside any
//!                                    partition directory.
//!   <partition_id_hex>/
//!     partition.json               — the PORTABLE partition record.
//!     active/ packs/ manifests/
//! ```
//!
//! **The guarantee this schema exists to make structural, not aspirational:**
//! retention must reach a person partition identically to a household
//! partition. [`PartitionStore`](crate::store::PartitionStore) loads
//! [`PartitionRecord`] (portable: retention class, key epoch, timestamps)
//! but never loads or holds a [`Subject`] — `subject` is read only inside
//! [`crate::store::PartitionStore::create`], to verify the derivation, and
//! is then written straight to the store-level local-binding file. No
//! accessor on `PartitionStore` returns a `Subject`. Any future code that
//! wants retention (or anything else) to behave differently for a person
//! than a household would have to *change a function signature* to reach
//! the subject at all — a visible act with an owner, not a quiet
//! conditional.

use crate::addressing::PartitionId;
use crate::error::{Result, StorageError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// File name of the portable, replicated partition record inside a
/// partition directory.
pub const PARTITION_RECORD_FILE: &str = "partition.json";

/// File name of the store-level, never-replicated local binding record.
/// Lives at the store root, **not** inside any partition directory — see
/// the module docs and spec §R.4/Q2.
pub const LOCAL_BINDINGS_FILE: &str = "partitions.local.json";

/// The closed retention-class vocabulary (spec §3.4). Each class changes
/// GC behaviour; a class that only labels is a taxonomy and does not
/// belong here. Deliberately excludes: any retention *period*
/// (`retain_days`, `expires_at`), a `legal_hold`/`hold` class, an
/// `audit`/`compliance` class, and any access-time or access-count field —
/// each refusal is load-bearing and is spelled out in the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    /// GC may drop unreferenced content aggressively, unprompted by policy.
    Ephemeral,
    /// GC drops unreferenced content when GC is asked to run. The default.
    Standard,
    /// GC never drops content, referenced or not; it repacks for
    /// utilization only. Destruction happens by destroying the whole
    /// partition, never incidentally.
    Durable,
}

/// The closed encryption-mode vocabulary (spec §3.2, added per §R.2 /
/// the security review's D-1). **Set at creation, never changeable in
/// place** — there is no `set_encryption_mode`, exactly as there is no
/// `set_retention_class`; no transition is legal in either direction.
///
/// This crate implements **no encryption** — the key design is
/// the security review's separate, concurrent workstream. This is the mode
/// flag only: the field that lets sealing fail closed later instead of
/// depending on every caller remembering, so it is cheap to add now and
/// expensive to backfill onto partitions already written. `plaintext` is
/// the only value any current caller can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionMode {
    /// No encryption. The only value any current caller can produce —
    /// `storage-kit` has no key-wrapping concept yet.
    Plaintext,
    /// Every write into this partition must be sealed (AEAD-wrapped).
    /// Reserved for when the key hierarchy lands; not enforced by this
    /// crate today.
    SealedRequired,
}

impl Default for RetentionClass {
    /// The documented default (spec §3.4, §4.4) — **not** applied silently
    /// by [`crate::store::PartitionStore::create`]. `PartitionSpec::retention_class`
    /// is a required field; a caller that wants `standard` must say so.
    /// This impl exists so `standard` has one canonical spelling for
    /// callers that choose to use it, not to let `create` retrofit it.
    fn default() -> Self {
        RetentionClass::Standard
    }
}

/// The subject-kind vocabulary for a local partition binding (spec §3.6,
/// amended by §R.5). **Closed, forever, at exactly three values**: `person`,
/// `household`, and `service`. Each is a derivation prefix for a principal
/// that gets its own partition — recording a derivation input is not adding
/// a taxonomy, and this enum being closed is what makes that true.
///
/// `service` is a **principal kind**, not a loosening of the closed-vocabulary
/// guardrail: the security review ruled that a headless service principal
/// needs its own partition because its key cannot be a second wrap of a
/// person's — e.g. division CI must not run under a person's principal. It
/// describes a *principal without a human*, not a *kind of customer*.
///
/// **Permanently banned, and this is the guardrail that still holds without
/// exception:** a *segment* value — `business`, `org`, `team`, `project`,
/// `client`, `division` — is the banned segment field wearing a
/// storage-layer costume and requires an explicit maintainer decision before
/// it could ever exist. A division household is a `household`, identical in
/// every recorded byte to a family household except the free-text `label`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Person,
    Household,
    Service,
}

impl SubjectKind {
    /// The domain-separator prefix hashed to derive a [`PartitionId`] for
    /// this kind of subject — mirrors [`PartitionId::for_person`] /
    /// [`PartitionId::for_household`] / [`PartitionId::for_service`].
    fn derivation_prefix(self) -> &'static str {
        match self {
            SubjectKind::Person => "person",
            SubjectKind::Household => "household",
            SubjectKind::Service => "service",
        }
    }
}

/// A partition's subject: which principal it was provisioned for. Recorded
/// only in the store-level [`LOCAL_BINDINGS_FILE`], never inside a
/// partition directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub kind: SubjectKind,
    pub id: String,
}

/// The reserved key-material slot inside [`PartitionRecord`]. `kek_ref` and
/// `kek_scheme` are opaque and unresolved today — storage-kit never parses,
/// resolves, or logs either field. Both are `null` until the key hierarchy
/// lands (the security review, concurrent, out of scope here); a non-null
/// value is rejected on read, fail-closed, the same discipline as the
/// pack/idx reserved fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionKey {
    /// The epoch new writes are stamped with. `0` until wrapping lands.
    pub current_epoch: u32,
    /// Reserved. Must be `null` today. Never a path, a URL, or key
    /// material — an opaque reference only, resolved by a custody layer
    /// above this crate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek_ref: Option<String>,
    /// Reserved. Must be `null` today. The tag for *how* `kek_ref` is to
    /// be interpreted, once it means something.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek_scheme: Option<String>,
}

impl PartitionKey {
    /// The only value this crate ever writes: epoch 0, both reserved
    /// fields null. There is no API to supply a non-default value —
    /// `PartitionSpec` carries no key fields at all.
    fn reserved() -> Self {
        PartitionKey {
            current_epoch: 0,
            kek_ref: None,
            kek_scheme: None,
        }
    }

    /// Fail-closed check: reject a record whose reserved fields are
    /// non-null. Never includes the offending value in the error — only
    /// that one was present — because `kek_ref`/`kek_scheme` must never be
    /// logged.
    fn reject_if_non_null(&self) -> Result<()> {
        if self.kek_ref.is_some() {
            return Err(StorageError::CorruptManifest(
                "partition.json: key.kek_ref is reserved and must be null".into(),
            ));
        }
        if self.kek_scheme.is_some() {
            return Err(StorageError::CorruptManifest(
                "partition.json: key.kek_scheme is reserved and must be null".into(),
            ));
        }
        Ok(())
    }
}

/// `partition.json` — the portable partition record. Replicated verbatim
/// with the data (spec §3.2): retention class and key state are properties
/// of the bytes, not of the store root they happen to sit in today.
///
/// Contains no principal id, household id, member list, wrap, salt, KDF
/// parameter, or factor — see the module docs and [`Subject`], which is
/// recorded only in the separate, never-replicated local bindings file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionRecord {
    pub format_version: u32,
    /// 32 lowercase hex chars. Must equal the containing directory name;
    /// checked on load.
    pub partition_id: String,
    /// Set at creation, never changeable in place. There is no
    /// `set_encryption_mode` — see [`EncryptionMode`]. Replicated with the
    /// data and subject to the same anti-laundering rule as
    /// `retention_class` (spec §3.8): [`copy_partition_record`] fails if a
    /// push would change a destination's `encryption_mode`.
    pub encryption_mode: EncryptionMode,
    /// Set at creation, immutable forever. There is no setter.
    pub retention_class: RetentionClass,
    pub key: PartitionKey,
    /// RFC 3339, UTC. Provisioning time of the *partition*, not of a copy —
    /// carried verbatim by [`copy_partition_record`].
    pub created_at: String,
}

/// Input to [`crate::store::PartitionStore::create`]. Deliberately carries
/// no default retention class and no default encryption mode: both fields
/// are required, so a caller must choose. "Retention decided before ingest,
/// not retrofitted" cannot be enforced by a constructor that silently fills
/// one in — the same discipline applies to `encryption_mode`, which is the
/// field that makes sealed-by-default fail closed rather than depending on
/// every caller remembering.
#[derive(Debug, Clone)]
pub struct PartitionSpec {
    pub subject: Subject,
    pub retention_class: RetentionClass,
    pub encryption_mode: EncryptionMode,
    pub label: Option<String>,
}

/// One entry in the store-level [`LOCAL_BINDINGS_FILE`]: the subject a
/// partition was provisioned for, plus a free-text label. Never parsed for
/// semantics beyond `subject`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalBinding {
    pub subject: Subject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalBindingsFile {
    format_version: u32,
    #[serde(default)]
    bindings: BTreeMap<String, LocalBinding>,
}

fn record_path(store_root: &Path, partition_id: PartitionId) -> PathBuf {
    store_root
        .join(partition_id.to_hex())
        .join(PARTITION_RECORD_FILE)
}

fn local_bindings_path(store_root: &Path) -> PathBuf {
    store_root.join(LOCAL_BINDINGS_FILE)
}

/// Load and validate `partition.json` for `partition_id` under
/// `store_root`. Fail-closed: rejects a `format_version` this build cannot
/// read, a `partition_id` that disagrees with the containing directory
/// name, and any non-null value in the reserved `key` fields.
pub(crate) fn load_record(store_root: &Path, partition_id: PartitionId) -> Result<PartitionRecord> {
    let path = record_path(store_root, partition_id);
    let bytes = fs::read(&path)?;
    let record: PartitionRecord = serde_json::from_slice(&bytes)?;

    if record.format_version != crate::FORMAT_VERSION {
        return Err(StorageError::CorruptManifest(format!(
            "partition.json format_version {} unreadable by this build (reads {})",
            record.format_version,
            crate::FORMAT_VERSION
        )));
    }
    if record.partition_id != partition_id.to_hex() {
        return Err(StorageError::PartitionBoundary(format!(
            "partition.json partition_id {} does not match containing directory {}",
            record.partition_id,
            partition_id.to_hex()
        )));
    }
    record.key.reject_if_non_null()?;

    Ok(record)
}

/// `true` if `partition_id` has a `partition.json` under `store_root` —
/// the sole authoritative provisioning marker.
pub(crate) fn is_provisioned(store_root: &Path, partition_id: PartitionId) -> bool {
    record_path(store_root, partition_id).is_file()
}

fn write_record(
    store_root: &Path,
    partition_id: PartitionId,
    record: &PartitionRecord,
) -> Result<()> {
    let path = record_path(store_root, partition_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(record)?;
    fs::write(&path, json)?;
    Ok(())
}

fn load_local_bindings(store_root: &Path) -> Result<LocalBindingsFile> {
    let path = local_bindings_path(store_root);
    if !path.is_file() {
        return Ok(LocalBindingsFile {
            format_version: crate::FORMAT_VERSION,
            bindings: BTreeMap::new(),
        });
    }
    let bytes = fs::read(&path)?;
    let file: LocalBindingsFile = serde_json::from_slice(&bytes)?;
    Ok(file)
}

fn save_local_bindings(store_root: &Path, file: &LocalBindingsFile) -> Result<()> {
    fs::create_dir_all(store_root)?;
    let json = serde_json::to_string_pretty(file)?;
    fs::write(local_bindings_path(store_root), json)?;
    Ok(())
}

/// Write the local `subject`/`label` binding for `partition_id` into the
/// store-level [`LOCAL_BINDINGS_FILE`]. Called by
/// [`crate::store::PartitionStore::create`] only — never by `open`, and
/// never with the partition directory as the target.
pub(crate) fn bind_local(
    store_root: &Path,
    partition_id: PartitionId,
    subject: &Subject,
    label: &Option<String>,
) -> Result<()> {
    let mut file = load_local_bindings(store_root)?;
    file.bindings.insert(
        partition_id.to_hex(),
        LocalBinding {
            subject: subject.clone(),
            label: label.clone(),
        },
    );
    save_local_bindings(store_root, &file)
}

/// Verify `PartitionId::derive("{kind}:{id}")` reproduces `partition_id`,
/// mirroring [`PartitionId::for_person`]/[`PartitionId::for_household`].
/// A partition cannot be provisioned under a subject it was not derived
/// from.
pub(crate) fn verify_derivation(partition_id: PartitionId, subject: &Subject) -> Result<()> {
    let expected = PartitionId::derive(&format!(
        "{}:{}",
        subject.kind.derivation_prefix(),
        subject.id
    ));
    if expected != partition_id {
        return Err(StorageError::PartitionBoundary(format!(
            "partition {} was not derived from subject {{kind: {:?}, id: {}}}",
            partition_id.to_hex(),
            subject.kind,
            subject.id
        )));
    }
    Ok(())
}

/// Build the portable record `create()` writes: the reserved key block,
/// the provided retention class and encryption mode, and the current
/// timestamp.
pub(crate) fn new_record(
    partition_id: PartitionId,
    retention_class: RetentionClass,
    encryption_mode: EncryptionMode,
) -> PartitionRecord {
    PartitionRecord {
        format_version: crate::FORMAT_VERSION,
        partition_id: partition_id.to_hex(),
        encryption_mode,
        retention_class,
        key: PartitionKey::reserved(),
        created_at: now_rfc3339(),
    }
}

pub(crate) fn write_new_record(
    store_root: &Path,
    partition_id: PartitionId,
    record: &PartitionRecord,
) -> Result<()> {
    write_record(store_root, partition_id, record)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Copy `partition.json` from `source_store_root` to `dest_store_root` for
/// `partition_id` (spec §3.8). Copies the portable record only — never
/// [`LOCAL_BINDINGS_FILE`], which is not inside any partition directory and
/// so is out of reach of a per-partition copy by construction.
///
/// **Fails if the destination already holds a record whose
/// `retention_class` or `encryption_mode` differs from the source's.**
/// Replication may not change either — that is the laundering hole this
/// closes (spec §3.8 rule 2). A replica that lost `sealed-required` would
/// accept plaintext writes into a partition that must never hold any, which
/// is the same hole as retention laundering wearing a different hat.
pub fn copy_partition_record(
    source_store_root: &Path,
    dest_store_root: &Path,
    partition_id: PartitionId,
) -> Result<()> {
    let source_path = record_path(source_store_root, partition_id);
    if !source_path.is_file() {
        return Err(StorageError::PartitionNotProvisioned(partition_id.to_hex()));
    }
    let source_record = load_record(source_store_root, partition_id)?;

    let dest_path = record_path(dest_store_root, partition_id);
    if dest_path.is_file() {
        let dest_record = load_record(dest_store_root, partition_id)?;
        if dest_record.retention_class != source_record.retention_class {
            return Err(StorageError::PartitionBoundary(format!(
                "copy_partition_record: destination retention_class for {} would change ({:?} -> {:?}); replication may not change a retention class",
                partition_id.to_hex(),
                dest_record.retention_class,
                source_record.retention_class,
            )));
        }
        if dest_record.encryption_mode != source_record.encryption_mode {
            return Err(StorageError::PartitionBoundary(format!(
                "copy_partition_record: destination encryption_mode for {} would change ({:?} -> {:?}); replication may not change an encryption mode",
                partition_id.to_hex(),
                dest_record.encryption_mode,
                source_record.encryption_mode,
            )));
        }
    }

    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Copy verbatim (byte-for-byte) so `created_at` and every other field
    // carry over exactly as written at provisioning time.
    fs::copy(&source_path, &dest_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn subject_kind_rejects_a_fourth_value() {
        // `service` is now legal (§R.5) — the closed vocabulary is exactly
        // three values. What must stay permanently rejected is a *segment*
        // value wearing a storage-layer costume, per §3.6's guardrail.
        let json = r#"{"kind":"business","id":"biz-1"}"#;
        let result: std::result::Result<Subject, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "subject.kind must be a closed three-value vocabulary (person, household, service) \
             — a segment value like `business` must never deserialize"
        );
    }

    #[test]
    fn subject_kind_accepts_person_household_and_service() {
        for json in [
            r#"{"kind":"person","id":"a"}"#,
            r#"{"kind":"household","id":"h"}"#,
            r#"{"kind":"service","id":"svc-1"}"#,
        ] {
            let result: std::result::Result<Subject, _> = serde_json::from_str(json);
            assert!(result.is_ok(), "expected {json} to deserialize");
        }
    }

    #[test]
    fn encryption_mode_rejects_a_third_value() {
        let json = r#""sealed""#;
        let result: std::result::Result<EncryptionMode, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "encryption_mode must be a closed two-value vocabulary (plaintext, sealed-required)"
        );
    }

    #[test]
    fn encryption_mode_accepts_plaintext_and_sealed_required() {
        for (json, expected) in [
            (r#""plaintext""#, EncryptionMode::Plaintext),
            (r#""sealed-required""#, EncryptionMode::SealedRequired),
        ] {
            let result: EncryptionMode = serde_json::from_str(json).unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn retention_class_default_is_standard() {
        assert_eq!(RetentionClass::default(), RetentionClass::Standard);
    }

    #[test]
    fn partition_key_reserved_fields_are_null() {
        let key = PartitionKey::reserved();
        assert!(key.kek_ref.is_none());
        assert!(key.kek_scheme.is_none());
        assert_eq!(key.current_epoch, 0);
    }

    #[test]
    fn partition_key_rejects_non_null_kek_ref() {
        let key = PartitionKey {
            current_epoch: 0,
            kek_ref: Some("anything".into()),
            kek_scheme: None,
        };
        assert!(key.reject_if_non_null().is_err());
    }

    #[test]
    fn partition_key_rejects_non_null_kek_scheme() {
        let key = PartitionKey {
            current_epoch: 0,
            kek_ref: None,
            kek_scheme: Some("anything".into()),
        };
        assert!(key.reject_if_non_null().is_err());
    }

    #[test]
    fn null_and_empty_string_kek_ref_are_distinct() {
        let null_key = PartitionKey::reserved();
        let empty_key = PartitionKey {
            current_epoch: 0,
            kek_ref: Some(String::new()),
            kek_scheme: None,
        };
        assert_ne!(null_key.kek_ref, empty_key.kek_ref);
        // Both must round-trip through JSON without collapsing into one another.
        let null_json = serde_json::to_string(&null_key).unwrap();
        let empty_json = serde_json::to_string(&empty_key).unwrap();
        assert_ne!(null_json, empty_json);
        let round_tripped: PartitionKey = serde_json::from_str(&empty_json).unwrap();
        assert_eq!(round_tripped.kek_ref, Some(String::new()));
    }

    #[test]
    fn verify_derivation_accepts_matching_subject() {
        let subject = Subject {
            kind: SubjectKind::Person,
            id: "acct-1".into(),
        };
        let partition_id = PartitionId::for_person("acct-1");
        assert!(verify_derivation(partition_id, &subject).is_ok());
    }

    #[test]
    fn verify_derivation_rejects_mismatched_subject() {
        let subject = Subject {
            kind: SubjectKind::Person,
            id: "acct-1".into(),
        };
        let wrong_id = PartitionId::for_person("acct-2");
        assert!(verify_derivation(wrong_id, &subject).is_err());

        let household_id = PartitionId::for_household("acct-1");
        assert!(verify_derivation(household_id, &subject).is_err());
    }

    #[test]
    fn verify_derivation_accepts_matching_service_subject() {
        let subject = Subject {
            kind: SubjectKind::Service,
            id: "svc-ci-1".into(),
        };
        let partition_id = PartitionId::for_service("svc-ci-1");
        assert!(verify_derivation(partition_id, &subject).is_ok());

        // A service subject must not verify against a person/household
        // partition derived from the same raw id — the domain prefix keeps
        // the three kinds from colliding.
        let person_id = PartitionId::for_person("svc-ci-1");
        assert!(verify_derivation(person_id, &subject).is_err());
    }

    #[test]
    fn copy_partition_record_refuses_retention_class_change() {
        let source_root = tempdir().unwrap();
        let dest_root = tempdir().unwrap();
        let partition_id = PartitionId::for_person("copy-test");

        let source_record = new_record(
            partition_id,
            RetentionClass::Durable,
            EncryptionMode::Plaintext,
        );
        write_new_record(source_root.path(), partition_id, &source_record).unwrap();

        let dest_record = new_record(
            partition_id,
            RetentionClass::Ephemeral,
            EncryptionMode::Plaintext,
        );
        write_new_record(dest_root.path(), partition_id, &dest_record).unwrap();

        let err = copy_partition_record(source_root.path(), dest_root.path(), partition_id)
            .expect_err("retention class laundering must be refused");
        let msg = format!("{err}");
        assert!(msg.contains("retention"), "unexpected error: {msg}");
    }

    #[test]
    fn copy_partition_record_refuses_encryption_mode_change() {
        let source_root = tempdir().unwrap();
        let dest_root = tempdir().unwrap();
        let partition_id = PartitionId::for_person("copy-test-encryption");

        let source_record = new_record(
            partition_id,
            RetentionClass::Standard,
            EncryptionMode::SealedRequired,
        );
        write_new_record(source_root.path(), partition_id, &source_record).unwrap();

        let dest_record = new_record(
            partition_id,
            RetentionClass::Standard,
            EncryptionMode::Plaintext,
        );
        write_new_record(dest_root.path(), partition_id, &dest_record).unwrap();

        let err = copy_partition_record(source_root.path(), dest_root.path(), partition_id)
            .expect_err(
                "encryption mode laundering must be refused — a replica must not be able to lose \
             sealed-required",
            );
        let msg = format!("{err}");
        assert!(msg.contains("encryption_mode"), "unexpected error: {msg}");
    }

    #[test]
    fn copy_partition_record_succeeds_when_retention_class_matches() {
        let source_root = tempdir().unwrap();
        let dest_root = tempdir().unwrap();
        let partition_id = PartitionId::for_person("copy-test-ok");

        let source_record = new_record(
            partition_id,
            RetentionClass::Standard,
            EncryptionMode::Plaintext,
        );
        write_new_record(source_root.path(), partition_id, &source_record).unwrap();

        copy_partition_record(source_root.path(), dest_root.path(), partition_id).unwrap();

        let copied = load_record(dest_root.path(), partition_id).unwrap();
        assert_eq!(copied, source_record);
    }

    #[test]
    fn copy_partition_record_succeeds_on_a_fresh_destination() {
        let source_root = tempdir().unwrap();
        let dest_root = tempdir().unwrap();
        let partition_id = PartitionId::for_household("copy-test-fresh");

        let source_record = new_record(
            partition_id,
            RetentionClass::Ephemeral,
            EncryptionMode::Plaintext,
        );
        write_new_record(source_root.path(), partition_id, &source_record).unwrap();

        copy_partition_record(source_root.path(), dest_root.path(), partition_id).unwrap();
        let copied = load_record(dest_root.path(), partition_id).unwrap();
        assert_eq!(copied, source_record);
    }

    #[test]
    fn copy_partition_record_never_touches_local_bindings() {
        let source_root = tempdir().unwrap();
        let dest_root = tempdir().unwrap();
        let partition_id = PartitionId::for_person("copy-test-no-local");

        let subject = Subject {
            kind: SubjectKind::Person,
            id: "copy-test-no-local".into(),
        };
        bind_local(source_root.path(), partition_id, &subject, &None).unwrap();
        let source_record = new_record(
            partition_id,
            RetentionClass::Standard,
            EncryptionMode::Plaintext,
        );
        write_new_record(source_root.path(), partition_id, &source_record).unwrap();

        copy_partition_record(source_root.path(), dest_root.path(), partition_id).unwrap();

        assert!(
            !local_bindings_path(dest_root.path()).exists(),
            "copy_partition_record must never write partitions.local.json"
        );
    }
}
