//! Packfile on-disk layout — format v3, per the 2026-09-23
//! storage-addressing rulings (the design and security reviews,
//! Branch A). Entry meta is **54 bytes**; the `context` reservation the
//! spec this superseded (the format-reservations spec)
//! carried is withdrawn by both rulings — `(hash, context)` addressing
//! never lands, so there is no 16-byte slot to grow into. `key_epoch`
//! (u32, equality-only, single legal value `0` today) and `flags` (single
//! legal value `0x00`, no bit assigned) remain exactly as that spec
//! reserved them.
//!
//! Two files per pack: `<pack_id>.pack` (data) and `<pack_id>.idx` (index).
//! The index is git-pack style: derived and rebuildable from the `.pack`
//! file alone, and is never treated as a source of truth — losing an `.idx`
//! is a `verify`/rebuild-away, not data loss.
//!
//! `.pack` layout:
//! ```text
//! header:  magic "BCPK" (4B) | format_ver u32 LE (=3) | partition_id (16B)
//! entry*:  hash (32B) | codec (1B) | flags (1B) | key_epoch u32 LE (4B)
//!          | uncompressed_len u64 LE (8B) | stored_len u64 LE (8B)
//!          | payload (stored_len bytes)
//! trailer: entry_count u64 LE | pack_content_hash (32B)
//! ```
//! `pack_content_hash` is the BLAKE3 hash of every byte in the file *before*
//! the trailer (header + all entries) — it is also the pack's own content
//! address: sealed packs are named `<pack_content_hash_hex>.pack`.
//!
//! The trailer is only ever written when a pack is **sealed**; the
//! currently-open active pack has no trailer and is rebuilt by sequential
//! scan on reopen (crash-safe by construction — a scan simply stops at the
//! last complete entry).
//!
//! **The `.idx` is a lossless projection of the pack.** Every field in an
//! idx record also exists in the pack entry it describes; the idx adds only
//! the byte offset, the one fact the pack cannot carry about itself:
//! `IDX_RECORD_LEN == ENTRY_META_LEN + 8`, asserted at compile time below.
//! This also **restores `flags` to the index**, which v2 dropped — the
//! projection invariant is worth more than the byte.
//!
//! **Fail-closed enforcement, on both sides.** The writer here never emits
//! anything but the reserved values (`flags == 0x00`, `key_epoch == 0`) —
//! [`PackWriter::append`] takes no parameters to supply them, by
//! construction. [`EntryMeta::validate_reserved`] is the reader-side half:
//! it is called on every entry [`ImmutableStore::get`](crate::store::ImmutableStore::get)
//! hands a caller, and rejects a non-reserved value with
//! [`StorageError::CorruptPack`], naming the field. It is **not** called on
//! the raw byte-copy path ([`PackWriter::append_raw`], [`get_raw_at`],
//! `rebuild_index_entries`, `read_index`) — those exist so a meta-preserving
//! copy (GC's repack) can move an entry forward without decoding or
//! trusting its meaning, which is what keeps GC key-blind once encryption
//! lands. A v3 reader must never silently *ignore* a field it cannot
//! honour when it is actually interpreting content; it does not need to
//! interpret meta at all to relocate the bytes.
//!
//! `codec` gains a third discriminant, `Sealed = 2`, reserved and rejected
//! at v3 (the security review's request, adopted in
//! the format-reservations spec §R.2) — defined now so
//! the value is not claimed for anything else, and becomes legal at the
//! seal-freeze version. This crate implements **no encryption**; that is a
//! separate, not-yet-landed workstream.

use crate::addressing::{Hash, PartitionId, HASH_LEN, PARTITION_ID_LEN};
use crate::error::{Result, StorageError};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const PACK_MAGIC: [u8; 4] = *b"BCPK";
pub const IDX_MAGIC: [u8; 4] = *b"BCIX";
pub const FORMAT_VERSION: u32 = 3;
pub const HEADER_LEN: usize = 4 + 4 + PARTITION_ID_LEN;
pub const TRAILER_LEN: usize = 8 + HASH_LEN;
/// `hash(32) | codec(1) | flags(1) | key_epoch(4) | uncompressed_len(8) |
/// stored_len(8)` = 54. Pinned by `ENTRY_META_LEN_IS_54` below — growing
/// this is a compile error with a ruling attached, not a diff someone skims.
pub const ENTRY_META_LEN: usize = HASH_LEN + 1 + 1 + 4 + 8 + 8;

const _ENTRY_META_LEN_IS_54: () = assert!(
    ENTRY_META_LEN == 54,
    "ENTRY_META_LEN must be 54 per the 2026-09-23 storage-addressing rulings (Branch A) \
     — see storage-addressing-hash-context-ruling-2026-09-23.md"
);

/// Storage codec applied to an entry's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Payload is stored uncompressed (used when Zstd does not help, e.g.
    /// already-compressed or very small inputs).
    Raw = 0,
    /// Payload is Zstd-compressed.
    Zstd = 1,
    /// Payload is AEAD-sealed. **Reserved and rejected at format v3** — the
    /// discriminant is defined now (the security review's request) so it is
    /// not claimed for anything else; it becomes legal at the seal-freeze
    /// version. This crate implements no encryption today and no writer
    /// here ever emits this value.
    Sealed = 2,
}

impl Codec {
    fn from_u8(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Codec::Raw),
            1 => Ok(Codec::Zstd),
            2 => Ok(Codec::Sealed),
            other => Err(StorageError::CorruptPack(format!(
                "unknown codec byte {other}"
            ))),
        }
    }
}

/// Metadata for one stored entry (payload excluded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryMeta {
    pub hash: Hash,
    pub codec: Codec,
    /// Reserved. The only legal value at format v3 is `0x00` — no bit is
    /// assigned, now or in this change. See the module docs: `flags` is
    /// deliberately left wholly unassigned rather than given a `SEALED`
    /// bit, because `Codec::Sealed` is the sole indicator that a payload is
    /// sealed and a second field restating the same fact is a duplicated
    /// state that will eventually disagree with the original.
    pub flags: u8,
    /// A u32 opaque key *selector*. Today its only interpretation is a
    /// monotonic per-partition epoch counter; the sole legal value is `0`,
    /// since this crate has no key-wrapping concept yet. **Equality only**
    /// — code that orders it (`key_epoch < current_epoch`) has silently
    /// spent the future key-table-index reinterpretation and is a defect.
    pub key_epoch: u32,
    pub uncompressed_len: u64,
    pub stored_len: u64,
}

impl EntryMeta {
    /// Fail-closed check that every field reserved at format v3 carries its
    /// sole legal value. Called on every entry [`ImmutableStore::get`]
    /// hands to a caller — the boundary that decodes and trusts the
    /// payload's meaning. **Deliberately not called** on the raw byte-copy
    /// path (`append_raw`, [`get_raw_at`], `rebuild_index_entries`,
    /// `read_index`): a meta-preserving copy relocates bytes without
    /// interpreting what they mean, which is what keeps GC key-blind.
    ///
    /// [`ImmutableStore::get`]: crate::store::ImmutableStore::get
    pub fn validate_reserved(&self) -> Result<()> {
        if self.flags != 0x00 {
            return Err(StorageError::CorruptPack(format!(
                "entry {}: flags is reserved and must be 0x00, got {:#04x}",
                self.hash, self.flags
            )));
        }
        if self.key_epoch != 0 {
            return Err(StorageError::CorruptPack(format!(
                "entry {}: key_epoch is reserved and must be 0, got {}",
                self.hash, self.key_epoch
            )));
        }
        if self.codec == Codec::Sealed {
            return Err(StorageError::CorruptPack(format!(
                "entry {}: codec Sealed is reserved and rejected at format v3",
                self.hash
            )));
        }
        Ok(())
    }
}

/// Location of a sealed entry: which pack, and byte offset of its entry
/// header within that pack.
#[derive(Debug, Clone, Copy)]
pub struct SealedLocation {
    pub pack_id: Hash,
    pub offset: u64,
}

const ZSTD_LEVEL: i32 = 3;

/// Compress `data`, falling back to raw storage if compression doesn't
/// actually shrink the payload (small or already-dense inputs).
pub fn encode(data: &[u8]) -> Result<(Codec, Vec<u8>)> {
    if data.is_empty() {
        return Ok((Codec::Raw, Vec::new()));
    }
    let compressed = zstd::stream::encode_all(data, ZSTD_LEVEL)
        .map_err(|e| StorageError::Compression(e.to_string()))?;
    if compressed.len() < data.len() {
        Ok((Codec::Zstd, compressed))
    } else {
        Ok((Codec::Raw, data.to_vec()))
    }
}

pub fn decode(codec: Codec, stored: &[u8]) -> Result<Vec<u8>> {
    match codec {
        Codec::Raw => Ok(stored.to_vec()),
        Codec::Zstd => {
            zstd::stream::decode_all(stored).map_err(|e| StorageError::Compression(e.to_string()))
        }
        // Unreachable in practice: every caller runs `EntryMeta::validate_reserved`
        // first, which rejects `Sealed` at v3. Kept as a hard error rather than
        // `unreachable!()` so a future caller that skips validation fails safe
        // instead of panicking.
        Codec::Sealed => Err(StorageError::CorruptPack(
            "codec Sealed is reserved and rejected at format v3; decode() must not be called \
             without EntryMeta::validate_reserved() first"
                .into(),
        )),
    }
}

fn write_header<W: Write>(w: &mut W, partition_id: &PartitionId) -> Result<()> {
    w.write_all(&PACK_MAGIC)?;
    w.write_all(&FORMAT_VERSION.to_le_bytes())?;
    w.write_all(partition_id.as_bytes())?;
    Ok(())
}

fn read_header<R: Read>(r: &mut R) -> Result<PartitionId> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if magic != PACK_MAGIC {
        return Err(StorageError::CorruptPack("bad magic".into()));
    }
    let mut ver = [0u8; 4];
    r.read_exact(&mut ver)?;
    let ver = u32::from_le_bytes(ver);
    if ver != FORMAT_VERSION {
        return Err(StorageError::CorruptPack(format!(
            "unsupported pack format_ver {ver} (expected {FORMAT_VERSION})"
        )));
    }
    let mut pid = [0u8; PARTITION_ID_LEN];
    r.read_exact(&mut pid)?;
    Ok(PartitionId::from_bytes(pid))
}

/// An open, append-only pack. Entries are appended one at a time; the
/// trailer is written only at `seal()` time.
pub struct PackWriter {
    path: PathBuf,
    partition_id: PartitionId,
    file: File,
    /// Byte length of the file so far (header + entries written).
    pub len: u64,
    pub entry_count: u64,
    /// In-memory offset index for entries written this process — avoids a
    /// re-scan to serve a `get()` against data not yet sealed.
    pub offsets: HashMap<Hash, u64>,
}

impl PackWriter {
    /// Open (creating if absent) the active pack at `path` for `partition_id`,
    /// rebuilding in-memory state by scanning any bytes already there
    /// (resuming after a crash or a prior process exit).
    pub fn open_active(path: &Path, partition_id: PartitionId) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let is_new = !path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;

        if is_new {
            write_header(&mut file, &partition_id)?;
            file.flush()?;
            return Ok(PackWriter {
                path: path.to_path_buf(),
                partition_id,
                file,
                len: HEADER_LEN as u64,
                entry_count: 0,
                offsets: HashMap::new(),
            });
        }

        // Resume: sequential scan for whatever complete entries exist.
        let mut reader = File::open(path)?;
        let found_partition = read_header(&mut reader)?;
        if found_partition != partition_id {
            return Err(StorageError::PartitionBoundary(format!(
                "active pack at {} belongs to partition {}, not {}",
                path.display(),
                found_partition.to_hex(),
                partition_id.to_hex()
            )));
        }
        let mut offsets = HashMap::new();
        let mut pos = HEADER_LEN as u64;
        let mut count = 0u64;
        loop {
            let entry_start = pos;
            match read_entry_meta_at(&mut reader, entry_start) {
                Ok(Some(meta)) => {
                    offsets.insert(meta.hash, entry_start);
                    pos = entry_start + ENTRY_META_LEN as u64 + meta.stored_len;
                    count += 1;
                }
                Ok(None) => break, // clean EOF at an entry boundary
                Err(_) => break,   // truncated/partial trailing entry — stop before it
            }
        }
        Ok(PackWriter {
            path: path.to_path_buf(),
            partition_id,
            file,
            len: pos,
            entry_count: count,
            offsets,
        })
    }

    /// Append one entry (dedup is the caller's responsibility — this always
    /// writes). Returns the byte offset the entry starts at. Always emits
    /// the reserved values for `flags`/`key_epoch` — there is no parameter
    /// to supply anything else; that is the writer-side half of the
    /// fail-closed rule (module docs).
    pub fn append(
        &mut self,
        hash: Hash,
        codec: Codec,
        uncompressed_len: u64,
        payload: &[u8],
    ) -> Result<u64> {
        let meta = EntryMeta {
            hash,
            codec,
            flags: 0x00,
            key_epoch: 0,
            uncompressed_len,
            stored_len: payload.len() as u64,
        };
        self.append_raw(&meta, payload)
    }

    /// Append one entry with an arbitrary, caller-supplied [`EntryMeta`] —
    /// the byte-exact primitive a meta-preserving copy (GC's repack) needs
    /// to relocate an entry without re-deriving `flags`/`key_epoch` from
    /// scratch. **Not** a route for ordinary callers to set reserved
    /// fields: `PartitionStore::put`
    /// only ever reaches this through [`PackWriter::append`], which hard-codes
    /// the reserved values. `packfile` is implementation, explicitly
    /// outside the interface lock (see `lib.rs`); this is the escape hatch
    /// that exists for exactly one job.
    pub fn append_raw(&mut self, meta: &EntryMeta, payload: &[u8]) -> Result<u64> {
        let offset = self.len;
        let mut buf = Vec::with_capacity(ENTRY_META_LEN + payload.len());
        buf.extend_from_slice(meta.hash.as_bytes());
        buf.push(meta.codec as u8);
        buf.push(meta.flags);
        buf.extend_from_slice(&meta.key_epoch.to_le_bytes());
        buf.extend_from_slice(&meta.uncompressed_len.to_le_bytes());
        buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        buf.extend_from_slice(payload);
        self.file.write_all(&buf)?;
        self.file.flush()?;
        self.len += buf.len() as u64;
        self.entry_count += 1;
        self.offsets.insert(meta.hash, offset);
        Ok(offset)
    }

    pub fn read_payload_at(&self, offset: u64) -> Result<(EntryMeta, Vec<u8>)> {
        let mut f = File::open(&self.path)?;
        read_entry_full_at(&mut f, offset)
    }

    /// Seal this pack: write the trailer, rename to its content-addressed
    /// final name (`<pack_content_hash>.pack`), and return the new id +
    /// path. The writer is consumed — callers open a fresh `PackWriter` for
    /// the next active pack.
    pub fn seal(mut self, packs_dir: &Path) -> Result<(Hash, PathBuf)> {
        self.file.flush()?;
        // Hash everything written so far (header + entries), excluding the
        // trailer we're about to append.
        let mut hasher = blake3::Hasher::new();
        let mut reader = File::open(&self.path)?;
        std::io::copy(&mut reader, &mut hasher)?;
        let pack_content_hash = Hash::from_bytes(*hasher.finalize().as_bytes());

        self.file.write_all(&self.entry_count.to_le_bytes())?;
        self.file.write_all(pack_content_hash.as_bytes())?;
        self.file.flush()?;

        let pack_id_hex = pack_content_hash.to_hex();
        let shard = PartitionId::shard_prefix(&pack_id_hex).to_string();
        let dest_dir = packs_dir.join(&shard);
        fs::create_dir_all(&dest_dir)?;
        let dest_path = dest_dir.join(format!("{pack_id_hex}.pack"));
        fs::rename(&self.path, &dest_path)?;

        // Build + persist the derived index alongside the sealed pack.
        let entries = rebuild_index_entries(&dest_path)?;
        write_index(
            &dest_path.with_extension("idx"),
            &self.partition_id,
            &entries,
        )?;

        Ok((pack_content_hash, dest_path))
    }

    pub fn partition_id(&self) -> PartitionId {
        self.partition_id
    }
}

fn read_entry_meta_at<R: Read + Seek>(r: &mut R, offset: u64) -> Result<Option<EntryMeta>> {
    r.seek(SeekFrom::Start(offset))?;
    let mut meta_buf = [0u8; ENTRY_META_LEN];
    match r.read_exact(&mut meta_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let hash = Hash::from_bytes(meta_buf[0..32].try_into().unwrap());
    let codec = Codec::from_u8(meta_buf[32])?;
    let flags = meta_buf[33];
    let key_epoch = u32::from_le_bytes(meta_buf[34..38].try_into().unwrap());
    let uncompressed_len = u64::from_le_bytes(meta_buf[38..46].try_into().unwrap());
    let stored_len = u64::from_le_bytes(meta_buf[46..54].try_into().unwrap());
    // Confirm the payload is actually present (not a torn write).
    let mut probe = vec![0u8; stored_len as usize];
    match r.read_exact(&mut probe) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    Ok(Some(EntryMeta {
        hash,
        codec,
        flags,
        key_epoch,
        uncompressed_len,
        stored_len,
    }))
}

fn read_entry_full_at<R: Read + Seek>(r: &mut R, offset: u64) -> Result<(EntryMeta, Vec<u8>)> {
    r.seek(SeekFrom::Start(offset))?;
    let mut meta_buf = [0u8; ENTRY_META_LEN];
    r.read_exact(&mut meta_buf)?;
    let hash = Hash::from_bytes(meta_buf[0..32].try_into().unwrap());
    let codec = Codec::from_u8(meta_buf[32])?;
    let flags = meta_buf[33];
    let key_epoch = u32::from_le_bytes(meta_buf[34..38].try_into().unwrap());
    let uncompressed_len = u64::from_le_bytes(meta_buf[38..46].try_into().unwrap());
    let stored_len = u64::from_le_bytes(meta_buf[46..54].try_into().unwrap());
    let mut payload = vec![0u8; stored_len as usize];
    r.read_exact(&mut payload)?;
    Ok((
        EntryMeta {
            hash,
            codec,
            flags,
            key_epoch,
            uncompressed_len,
            stored_len,
        },
        payload,
    ))
}

/// Fetch one entry's `(meta, payload)` **without** decoding, hash-verifying,
/// or validating reserved fields — the raw form a meta-preserving copy (GC's
/// repack) needs so it can relocate an entry without interpreting what it
/// means. Contrast [`get_at`], which is the validated, decoded, verified
/// form real content reads go through.
pub fn get_raw_at(pack_path: &Path, offset: u64) -> Result<(EntryMeta, Vec<u8>)> {
    let mut f = File::open(pack_path)?;
    read_entry_full_at(&mut f, offset)
}

/// Rebuild the full `(offset, meta)` list for a **sealed** pack by
/// sequential scan, ignoring/validating against the trailer if present.
pub fn rebuild_index_entries(pack_path: &Path) -> Result<Vec<(u64, EntryMeta)>> {
    let mut f = File::open(pack_path)?;
    let _partition_id = read_header(&mut f)?;
    let file_len = f.metadata()?.len();
    let scan_end = file_len.saturating_sub(TRAILER_LEN as u64);

    let mut out = Vec::new();
    let mut pos = HEADER_LEN as u64;
    while pos < scan_end {
        let entry_start = pos;
        let meta = read_entry_meta_at(&mut f, entry_start)?.ok_or_else(|| {
            StorageError::CorruptPack(format!(
                "truncated entry at offset {entry_start} in {}",
                pack_path.display()
            ))
        })?;
        pos = entry_start + ENTRY_META_LEN as u64 + meta.stored_len;
        out.push((entry_start, meta));
    }
    if pos != scan_end {
        return Err(StorageError::CorruptPack(format!(
            "entry scan did not land on trailer boundary in {}",
            pack_path.display()
        )));
    }
    Ok(out)
}

/// Read a sealed pack's trailer and verify `pack_content_hash` against the
/// actual bytes preceding it. Returns `(entry_count, pack_content_hash)`.
pub fn verify_trailer(pack_path: &Path) -> Result<(u64, Hash)> {
    let mut f = File::open(pack_path)?;
    let file_len = f.metadata()?.len();
    if file_len < (HEADER_LEN + TRAILER_LEN) as u64 {
        return Err(StorageError::CorruptPack(
            "pack too short for trailer".into(),
        ));
    }
    f.seek(SeekFrom::Start(file_len - TRAILER_LEN as u64))?;
    let mut trailer = [0u8; TRAILER_LEN];
    f.read_exact(&mut trailer)?;
    let entry_count = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
    let recorded_hash = Hash::from_bytes(trailer[8..40].try_into().unwrap());

    let mut hasher = blake3::Hasher::new();
    let body = File::open(pack_path)?;
    let mut limited = Read::take(body, file_len - TRAILER_LEN as u64);
    std::io::copy(&mut limited, &mut hasher)?;
    let actual_hash = Hash::from_bytes(*hasher.finalize().as_bytes());

    if actual_hash != recorded_hash {
        return Err(StorageError::CorruptPack(format!(
            "pack_content_hash mismatch in {}: trailer says {}, computed {}",
            pack_path.display(),
            recorded_hash,
            actual_hash
        )));
    }
    Ok((entry_count, actual_hash))
}

/// Fetch and decode one entry's payload from a sealed pack at `offset`,
/// verifying the stored bytes hash to the entry's own recorded hash. This
/// is the validated read path: [`EntryMeta::validate_reserved`] runs before
/// decode, so a non-reserved `flags`/`key_epoch`/`Sealed` codec is rejected
/// rather than silently honoured or ignored.
pub fn get_at(pack_path: &Path, offset: u64) -> Result<Vec<u8>> {
    let mut f = File::open(pack_path)?;
    let (meta, payload) = read_entry_full_at(&mut f, offset)?;
    meta.validate_reserved()?;
    let decoded = decode(meta.codec, &payload)?;
    let actual = Hash::of(&decoded);
    if actual != meta.hash {
        return Err(StorageError::HashMismatch {
            expected: meta.hash.to_hex(),
            actual: actual.to_hex(),
        });
    }
    if decoded.len() as u64 != meta.uncompressed_len {
        return Err(StorageError::CorruptPack(format!(
            "uncompressed_len mismatch for {}",
            meta.hash
        )));
    }
    Ok(decoded)
}

// ---------------------------------------------------------------------
// .idx — git-pack style derived index. Never authoritative; always
// rebuildable from the corresponding `.pack` via `rebuild_index_entries`.
// ---------------------------------------------------------------------

/// `hash(32) | offset(8) | codec(1) | flags(1) | key_epoch(4) |
/// uncompressed_len(8) | stored_len(8)` = 62 — the entry meta with `offset`
/// spliced in after `hash`, mirroring [`ENTRY_META_LEN`] exactly so a
/// single shared encoder/decoder serves both and the projection invariant
/// is obvious by inspection.
const IDX_RECORD_LEN: usize = HASH_LEN + 8 + 1 + 1 + 4 + 8 + 8;

const _IDX_RECORD_LEN_IS_ENTRY_META_LEN_PLUS_8: () = assert!(
    IDX_RECORD_LEN == ENTRY_META_LEN + 8,
    "IDX_RECORD_LEN must equal ENTRY_META_LEN + 8 — the idx adds only the byte offset, the one \
     fact the pack cannot carry about itself"
);

pub fn write_index(
    idx_path: &Path,
    partition_id: &PartitionId,
    entries: &[(u64, EntryMeta)],
) -> Result<()> {
    let mut sorted: Vec<&(u64, EntryMeta)> = entries.iter().collect();
    sorted.sort_by_key(|(_, m)| *m.hash.as_bytes());

    let mut buf = Vec::with_capacity(4 + 4 + PARTITION_ID_LEN + 8 + sorted.len() * IDX_RECORD_LEN);
    buf.extend_from_slice(&IDX_MAGIC);
    buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf.extend_from_slice(partition_id.as_bytes());
    buf.extend_from_slice(&(sorted.len() as u64).to_le_bytes());
    for (offset, meta) in sorted {
        buf.extend_from_slice(meta.hash.as_bytes());
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.push(meta.codec as u8);
        buf.push(meta.flags);
        buf.extend_from_slice(&meta.key_epoch.to_le_bytes());
        buf.extend_from_slice(&meta.uncompressed_len.to_le_bytes());
        buf.extend_from_slice(&meta.stored_len.to_le_bytes());
    }
    fs::write(idx_path, buf)?;
    Ok(())
}

/// Read a `.idx` file into a `hash -> (offset, meta)` map — the full
/// record, not merely the offset, so a caller (GC's meta-preserving copy)
/// can read an entry's meta straight from the loaded index without
/// touching the pack at all. Deliberately **not** validated here (see the
/// module docs): a corrupt/tampered idx is always recoverable via
/// `rebuild_index_entries`, and interpreting meta is `get()`'s job, not
/// the index loader's. Callers should not treat a missing/corrupt index as
/// an error condition for the store as a whole.
pub fn read_index(idx_path: &Path) -> Result<HashMap<Hash, (u64, EntryMeta)>> {
    let bytes = fs::read(idx_path)?;
    if bytes.len() < 4 + 4 + PARTITION_ID_LEN + 8 {
        return Err(StorageError::CorruptPack("idx too short".into()));
    }
    if bytes[0..4] != IDX_MAGIC {
        return Err(StorageError::CorruptPack("bad idx magic".into()));
    }
    let count_off = 4 + 4 + PARTITION_ID_LEN;
    let count = u64::from_le_bytes(bytes[count_off..count_off + 8].try_into().unwrap()) as usize;
    let mut out = HashMap::with_capacity(count);
    let mut pos = count_off + 8;
    for _ in 0..count {
        if pos + IDX_RECORD_LEN > bytes.len() {
            return Err(StorageError::CorruptPack("idx truncated".into()));
        }
        let hash = Hash::from_bytes(bytes[pos..pos + 32].try_into().unwrap());
        let offset = u64::from_le_bytes(bytes[pos + 32..pos + 40].try_into().unwrap());
        let codec = Codec::from_u8(bytes[pos + 40])?;
        let flags = bytes[pos + 41];
        let key_epoch = u32::from_le_bytes(bytes[pos + 42..pos + 46].try_into().unwrap());
        let uncompressed_len = u64::from_le_bytes(bytes[pos + 46..pos + 54].try_into().unwrap());
        let stored_len = u64::from_le_bytes(bytes[pos + 54..pos + 62].try_into().unwrap());
        out.insert(
            hash,
            (
                offset,
                EntryMeta {
                    hash,
                    codec,
                    flags,
                    key_epoch,
                    uncompressed_len,
                    stored_len,
                },
            ),
        );
        pos += IDX_RECORD_LEN;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn append_seal_and_read_back() {
        let dir = tempdir().unwrap();
        let packs_dir = dir.path().join("packs");
        let partition_id = PartitionId::derive("test-partition");

        let mut writer =
            PackWriter::open_active(&dir.path().join("active/active.pack"), partition_id).unwrap();
        let data = b"hello, packfile";
        let hash = Hash::of(data);
        let (codec, payload) = encode(data).unwrap();
        let offset = writer
            .append(hash, codec, data.len() as u64, &payload)
            .unwrap();

        let (pack_id, pack_path) = writer.seal(&packs_dir).unwrap();
        assert!(pack_path.exists());

        let (entry_count, content_hash) = verify_trailer(&pack_path).unwrap();
        assert_eq!(entry_count, 1);
        assert_eq!(content_hash, pack_id);

        let round_tripped = get_at(&pack_path, offset).unwrap();
        assert_eq!(round_tripped, data);
    }

    #[test]
    fn active_pack_resumes_after_reopen() {
        let dir = tempdir().unwrap();
        let active_path = dir.path().join("active/active.pack");
        let partition_id = PartitionId::derive("resume-partition");

        {
            let mut writer = PackWriter::open_active(&active_path, partition_id).unwrap();
            let (codec, payload) = encode(b"first").unwrap();
            writer
                .append(Hash::of(b"first"), codec, 5, &payload)
                .unwrap();
        }
        let writer = PackWriter::open_active(&active_path, partition_id).unwrap();
        assert_eq!(writer.entry_count, 1);
        assert!(writer.offsets.contains_key(&Hash::of(b"first")));
    }

    #[test]
    fn index_roundtrips() {
        let dir = tempdir().unwrap();
        let packs_dir = dir.path().join("packs");
        let partition_id = PartitionId::derive("idx-partition");
        let mut writer =
            PackWriter::open_active(&dir.path().join("active/active.pack"), partition_id).unwrap();
        let (codec, payload) = encode(b"index me").unwrap();
        writer
            .append(Hash::of(b"index me"), codec, 8, &payload)
            .unwrap();
        let (_pack_id, pack_path) = writer.seal(&packs_dir).unwrap();

        let idx_path = pack_path.with_extension("idx");
        let idx = read_index(&idx_path).unwrap();
        assert_eq!(idx.len(), 1);
        assert!(idx.contains_key(&Hash::of(b"index me")));

        // Index is derived — rebuilding from the pack alone must agree.
        let rebuilt = rebuild_index_entries(&pack_path).unwrap();
        assert_eq!(rebuilt.len(), 1);
        assert_eq!(rebuilt[0].1.hash, Hash::of(b"index me"));
    }

    #[test]
    fn entry_meta_len_is_54_and_idx_record_len_is_62() {
        assert_eq!(ENTRY_META_LEN, 54);
        assert_eq!(IDX_RECORD_LEN, 62);
    }

    #[test]
    fn append_always_emits_reserved_flags_and_key_epoch() {
        let dir = tempdir().unwrap();
        let partition_id = PartitionId::derive("reserved-values-partition");
        let mut writer =
            PackWriter::open_active(&dir.path().join("active/active.pack"), partition_id).unwrap();
        let (codec, payload) = encode(b"ordinary entry").unwrap();
        let offset = writer
            .append(Hash::of(b"ordinary entry"), codec, 14, &payload)
            .unwrap();
        let (meta, _) = writer.read_payload_at(offset).unwrap();
        assert_eq!(meta.flags, 0x00);
        assert_eq!(meta.key_epoch, 0);
        meta.validate_reserved().unwrap();
    }

    #[test]
    fn get_at_rejects_non_reserved_flags() {
        let dir = tempdir().unwrap();
        let packs_dir = dir.path().join("packs");
        let partition_id = PartitionId::derive("bad-flags-partition");
        let mut writer =
            PackWriter::open_active(&dir.path().join("active/active.pack"), partition_id).unwrap();
        let data = b"tampered meta";
        let (codec, payload) = encode(data).unwrap();
        let meta = EntryMeta {
            hash: Hash::of(data),
            codec,
            flags: 0x01, // non-reserved
            key_epoch: 0,
            uncompressed_len: data.len() as u64,
            stored_len: payload.len() as u64,
        };
        let offset = writer.append_raw(&meta, &payload).unwrap();
        let (_pack_id, pack_path) = writer.seal(&packs_dir).unwrap();

        let err = get_at(&pack_path, offset).expect_err("non-reserved flags must be rejected");
        assert!(matches!(err, StorageError::CorruptPack(_)));

        // The raw path is deliberately meta-blind and must still succeed —
        // this is the primitive GC's meta-preserving copy depends on.
        let (raw_meta, raw_payload) = get_raw_at(&pack_path, offset).unwrap();
        assert_eq!(raw_meta.flags, 0x01);
        assert_eq!(raw_payload, payload);
    }

    #[test]
    fn get_at_rejects_non_reserved_key_epoch() {
        let dir = tempdir().unwrap();
        let packs_dir = dir.path().join("packs");
        let partition_id = PartitionId::derive("bad-key-epoch-partition");
        let mut writer =
            PackWriter::open_active(&dir.path().join("active/active.pack"), partition_id).unwrap();
        let data = b"tampered epoch";
        let (codec, payload) = encode(data).unwrap();
        let meta = EntryMeta {
            hash: Hash::of(data),
            codec,
            flags: 0x00,
            key_epoch: 7, // non-reserved
            uncompressed_len: data.len() as u64,
            stored_len: payload.len() as u64,
        };
        let offset = writer.append_raw(&meta, &payload).unwrap();
        let (_pack_id, pack_path) = writer.seal(&packs_dir).unwrap();

        let err = get_at(&pack_path, offset).expect_err("non-reserved key_epoch must be rejected");
        assert!(matches!(err, StorageError::CorruptPack(_)));
    }

    #[test]
    fn get_at_rejects_sealed_codec_at_v3() {
        let dir = tempdir().unwrap();
        let packs_dir = dir.path().join("packs");
        let partition_id = PartitionId::derive("sealed-codec-partition");
        let mut writer =
            PackWriter::open_active(&dir.path().join("active/active.pack"), partition_id).unwrap();
        let data = b"sealed at v3, rejected";
        let meta = EntryMeta {
            hash: Hash::of(data),
            codec: Codec::Sealed,
            flags: 0x00,
            key_epoch: 0,
            uncompressed_len: data.len() as u64,
            stored_len: data.len() as u64,
        };
        let offset = writer.append_raw(&meta, data).unwrap();
        let (_pack_id, pack_path) = writer.seal(&packs_dir).unwrap();

        let err = get_at(&pack_path, offset).expect_err("Codec::Sealed must be rejected at v3");
        assert!(matches!(err, StorageError::CorruptPack(_)));
    }

    #[test]
    fn append_raw_preserves_meta_through_a_copy() {
        // The primitive GC's meta-preserving repack is built on: copy a
        // (meta, payload) pair, byte-for-byte, into a fresh pack, and read
        // the same meta back — no re-derivation, no silent re-stamping.
        let source_dir = tempdir().unwrap();
        let dest_dir = tempdir().unwrap();
        let partition_id = PartitionId::derive("append-raw-copy-partition");

        let mut source =
            PackWriter::open_active(&source_dir.path().join("active/active.pack"), partition_id)
                .unwrap();
        let data = b"copy me forward with meta intact";
        let (codec, payload) = encode(data).unwrap();
        let source_meta = EntryMeta {
            hash: Hash::of(data),
            codec,
            flags: 0x00,
            key_epoch: 0,
            uncompressed_len: data.len() as u64,
            stored_len: payload.len() as u64,
        };
        let source_offset = source.append_raw(&source_meta, &payload).unwrap();
        let (fetched_meta, fetched_payload) = source.read_payload_at(source_offset).unwrap();
        assert_eq!(fetched_meta, source_meta);

        let mut dest =
            PackWriter::open_active(&dest_dir.path().join("active/active.pack"), partition_id)
                .unwrap();
        let dest_offset = dest.append_raw(&fetched_meta, &fetched_payload).unwrap();
        let (copied_meta, copied_payload) = dest.read_payload_at(dest_offset).unwrap();

        assert_eq!(
            copied_meta, source_meta,
            "meta must survive the copy exactly"
        );
        assert_eq!(copied_payload, payload);
    }
}
