//! `(partition_id, content_id)` addressing — format v3, per the 2026-09-23
//! storage-addressing rulings (the design and security reviews, ruling
//! independently and converging on the same answer — Branch A).
//!
//! Physical storage is keyed by **hash alone** (BLAKE3 of the plaintext);
//! that is the only thing dedup and the packfile layer ever look at.
//! `Context` and `Address` — the 16-byte partition-scoped logical-identity
//! field the 2026-06 storage lock named as `(hash, context)` — are retired
//! from this crate entirely. Both rulings found the same thing from
//! different seats: the lock's dedup clause ("same bytes, different
//! contexts = same payload deduplicated under one hash") is satisfied by
//! hash-only keying and **violated** by compositing the storage key on a
//! context, so making `context` real was never a way to honour the lock —
//! it was the option that broke it. The lock's other half — context
//! travelling with the address, tracking logical identity separately —
//! already lives one layer up, in `bitchain`'s `ManifestEntry { path,
//! context, root_hash }`, which `bitchain` now owns byte-for-byte
//! (`storage-addressing-hash-context-ruling-2026-09-23.md`,
//! `storage-addressing-hash-context-ruling-security-2026-09-23.md`).
//!
//! `storage-kit` addresses by `(partition_id, content_id)` and knows
//! nothing of logical identity. It never will: `PartitionId::derive` is the
//! only free-form-string identity constructor this crate exposes, and its
//! use is gated by `PartitionStore::create`'s derivation check against a
//! closed `subject.kind` vocabulary — see `partition.rs`. A field minted
//! inline from an arbitrary string, with no such gate, cannot carry a
//! guardrail; that is why `Context::derive(&str)` is gone rather than
//! reserved.

use crate::error::{Result, StorageError};
use std::fmt;

/// Length in bytes of a BLAKE3 content hash.
pub const HASH_LEN: usize = 32;
/// Length in bytes of a partition id.
pub const PARTITION_ID_LEN: usize = 16;

/// A BLAKE3 content hash. This is the sole key for physical block storage
/// and dedup within a partition.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    /// Hash `bytes` with BLAKE3. This defines block identity for the entire
    /// storage engine — never change the algorithm without a format version
    /// bump.
    pub fn of(bytes: &[u8]) -> Self {
        Hash(*blake3::hash(bytes).as_bytes())
    }

    pub fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Hash(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| StorageError::InvalidAddress(format!("bad hash hex: {e}")))?;
        let arr: [u8; HASH_LEN] = bytes
            .try_into()
            .map_err(|_| StorageError::InvalidAddress("hash must be 32 bytes".into()))?;
        Ok(Hash(arr))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A 16-byte partition id: the physical storage boundary. Canonical
/// construction is `BLAKE3(household/namespace-id)[0:16]`. No pack ever
/// spans partitions; dedup and GC are both scoped to a single partition.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionId([u8; PARTITION_ID_LEN]);

impl PartitionId {
    /// Derive a canonical partition id from a household/namespace string.
    pub fn derive(namespace: &str) -> Self {
        let full = blake3::hash(namespace.as_bytes());
        let mut out = [0u8; PARTITION_ID_LEN];
        out.copy_from_slice(&full.as_bytes()[..PARTITION_ID_LEN]);
        PartitionId(out)
    }

    /// Derive the partition id for a **person's** own partition (R3,
    /// standalone-first identity):
    /// `PartitionId::derive("person:{account_id}")`. The `person:` prefix is
    /// the domain separator from [`PartitionId::for_household`] — a person
    /// and a household never land on the same partition even if
    /// `account_id` and a household id happen to coincide as strings.
    ///
    /// Additive: does not change how any existing `PartitionId` is derived
    /// or stored on disk. No dedup ever crosses a partition boundary (see
    /// the crate-root docs, "R3 partitions"); shared content is copied into
    /// a household partition, never referenced across partitions.
    pub fn for_person(account_id: &str) -> Self {
        PartitionId::derive(&format!("person:{account_id}"))
    }

    /// Derive the partition id for a **household's** shared partition (R3,
    /// standalone-first identity):
    /// `PartitionId::derive("household:{hid}")`. See
    /// [`PartitionId::for_person`] for the domain-separation rationale and
    /// the no-cross-partition-dedup rule.
    pub fn for_household(hid: &str) -> Self {
        PartitionId::derive(&format!("household:{hid}"))
    }

    /// Derive the partition id for a **service's** own partition (spec
    /// the format-reservations spec §R.5): a headless
    /// principal gets its own partition rather than a second wrap of a
    /// person's key, because its key cannot be derived by wrapping a
    /// person's — the security review ruled a service principal needs
    /// independent key custody so, e.g., division CI cannot run under a
    /// person's principal. `service:` is the domain-separator prefix,
    /// naming this the third and last member of the closed `subject.kind`
    /// vocabulary alongside [`PartitionId::for_person`] and
    /// [`PartitionId::for_household`] — see the module docs there for the
    /// domain-separation rationale and the no-cross-partition-dedup rule.
    pub fn for_service(service_id: &str) -> Self {
        PartitionId::derive(&format!("service:{service_id}"))
    }

    pub fn from_bytes(bytes: [u8; PARTITION_ID_LEN]) -> Self {
        PartitionId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PARTITION_ID_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| StorageError::InvalidAddress(format!("bad partition id hex: {e}")))?;
        let arr: [u8; PARTITION_ID_LEN] = bytes
            .try_into()
            .map_err(|_| StorageError::InvalidAddress("partition id must be 16 bytes".into()))?;
        Ok(PartitionId(arr))
    }

    /// The two-hex-char shard prefix used for the `packs/<prefix>/` fanout
    /// directory of the *pack id* (not the partition id itself) — kept here
    /// as a shared helper since both packfile and partition-store need the
    /// identical prefixing rule.
    pub fn shard_prefix(hex_id: &str) -> &str {
        &hex_id[..2.min(hex_id.len())]
    }
}

impl fmt::Debug for PartitionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PartitionId({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrips_through_hex() {
        let h = Hash::of(b"hello world");
        let hex = h.to_hex();
        let h2 = Hash::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn partition_id_derivation_is_deterministic() {
        let a = PartitionId::derive("household:acme");
        let b = PartitionId::derive("household:acme");
        assert_eq!(a, b);
    }

    #[test]
    fn for_person_matches_the_prefixed_derive_convention() {
        let a = PartitionId::for_person("acct-123");
        let b = PartitionId::derive("person:acct-123");
        assert_eq!(a, b);
    }

    #[test]
    fn for_household_matches_the_prefixed_derive_convention() {
        let a = PartitionId::for_household("hid-abc");
        let b = PartitionId::derive("household:hid-abc");
        assert_eq!(a, b);
    }

    #[test]
    fn person_and_household_partitions_are_domain_separated() {
        // Same raw id string, different domain prefix -- must never collide,
        // even though `PartitionId::for_household` reuses the exact bytes
        // "acme" that a bare `PartitionId::derive("acme")` would hash.
        let person = PartitionId::for_person("acme");
        let household = PartitionId::for_household("acme");
        assert_ne!(person, household);
    }

    #[test]
    fn for_person_is_deterministic() {
        let a = PartitionId::for_person("acct-123");
        let b = PartitionId::for_person("acct-123");
        assert_eq!(a, b);
    }

    #[test]
    fn for_service_matches_the_prefixed_derive_convention() {
        let a = PartitionId::for_service("svc-1");
        let b = PartitionId::derive("service:svc-1");
        assert_eq!(a, b);
    }

    #[test]
    fn for_service_is_deterministic() {
        let a = PartitionId::for_service("svc-1");
        let b = PartitionId::for_service("svc-1");
        assert_eq!(a, b);
    }

    #[test]
    fn service_partitions_are_domain_separated_from_person_and_household() {
        // Same raw id string across all three domain prefixes -- a service
        // id must never collide with a person or household id, even though
        // all three derive from the exact bytes "acme".
        let person = PartitionId::for_person("acme");
        let household = PartitionId::for_household("acme");
        let service = PartitionId::for_service("acme");
        assert_ne!(service, person);
        assert_ne!(service, household);
    }
}
