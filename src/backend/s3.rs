//! `S3Backend` — S3 / S3-compatible (Wasabi, B2, R2, MinIO) object storage.
//!
//! Each stored hash maps to exactly one object at
//! `<key_prefix>/<partition_hex>/<hash_hex>`; the object body is
//! `[codec_byte][payload]` using the same `Codec`/`encode`/`decode` bitchain
//! uses for its packfile entries, so a value written by `bitchain pack`
//! (once pushed) and one written by `S3Backend::put` decode identically.
//!
//! **Presigned direct-to-bucket uploads are the primary upload path**, per
//! the standing design note for this crate: server-proxied
//! uploads through this backend's `put()` incur AWS-style egress charges on
//! the way back down and don't fit the "any S3-compatible vendor" goal as
//! cleanly as a presigned PUT the client issues directly. `put()`/`get()`
//! here exist for administrative/CLI use (`push`/`pull`, `verify`, tests) —
//! real client uploads should call [`S3Backend::presigned_put_url`] and PUT
//! straight to the bucket. Quota enforcement belongs at presign-issuance
//! time, in the hosted control plane, never gated inside this OSS path.
//!
//! This crate's own test suite does not exercise `S3Backend` against a live
//! endpoint (it needs credentials and a bucket or a MinIO instance); checksum
//! header handling varies by vendor, so test against yours before relying on it.

use crate::addressing::{Hash, PartitionId};
use crate::backend::AsyncImmutableStore;
use crate::error::StorageError;
use crate::store::packfile::{decode, encode, Codec};
use aws_sdk_s3::presigning::PresigningConfig;
use bytes::Bytes;
use std::time::Duration;

pub struct S3Backend {
    client: aws_sdk_s3::Client,
    bucket: String,
    key_prefix: String,
    partition_id: PartitionId,
}

impl S3Backend {
    pub fn new(
        client: aws_sdk_s3::Client,
        bucket: impl Into<String>,
        key_prefix: impl Into<String>,
        partition_id: PartitionId,
    ) -> Self {
        S3Backend {
            client,
            bucket: bucket.into(),
            key_prefix: key_prefix.into(),
            partition_id,
        }
    }

    fn key_for(&self, hash: &Hash) -> String {
        format!(
            "{}/{}/{}",
            self.key_prefix.trim_end_matches('/'),
            self.partition_id.to_hex(),
            hash.to_hex()
        )
    }

    /// Presigned PUT URL for direct-to-bucket client upload of `hash`'s
    /// content. The caller is responsible for encoding the body the same
    /// way [`S3Backend::put`] would (`[codec_byte][payload]`) if it needs
    /// to be readable by this backend's `get()` — for a purely
    /// client-driven upload flow, prefer generating the URL for a raw
    /// object and let the server-side ingest path (not this backend) do
    /// the codec framing on confirmation.
    pub async fn presigned_put_url(
        &self,
        hash: &Hash,
        expires_in: Duration,
    ) -> Result<String, StorageError> {
        let presigned = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key_for(hash))
            .presigned(
                PresigningConfig::expires_in(expires_in)
                    .map_err(|e| StorageError::Backend(e.to_string()))?,
            )
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(presigned.uri().to_string())
    }

    pub async fn presigned_get_url(
        &self,
        hash: &Hash,
        expires_in: Duration,
    ) -> Result<String, StorageError> {
        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key_for(hash))
            .presigned(
                PresigningConfig::expires_in(expires_in)
                    .map_err(|e| StorageError::Backend(e.to_string()))?,
            )
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(presigned.uri().to_string())
    }
}

#[async_trait::async_trait]
impl AsyncImmutableStore for S3Backend {
    async fn get(&self, hash: &Hash) -> Result<Vec<u8>, StorageError> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key_for(hash))
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let body = resp
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .into_bytes();
        if body.is_empty() {
            return Err(StorageError::Backend("empty object body".into()));
        }
        let codec = match body[0] {
            0 => Codec::Raw,
            1 => Codec::Zstd,
            other => return Err(StorageError::Backend(format!("unknown codec byte {other}"))),
        };
        let decoded = decode(codec, &body[1..])?;
        let actual = Hash::of(&decoded);
        if actual != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash.to_hex(),
                actual: actual.to_hex(),
            });
        }
        Ok(decoded)
    }

    async fn put(&self, data: &[u8]) -> Result<Hash, StorageError> {
        let hash = Hash::of(data);
        if self.has(&hash).await.unwrap_or(false) {
            return Ok(hash); // dedup: skip a redundant PUT
        }
        let (codec, payload) = encode(data)?;
        let mut body = Vec::with_capacity(1 + payload.len());
        body.push(codec as u8);
        body.extend_from_slice(&payload);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key_for(&hash))
            .body(Bytes::from(body).into())
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(hash)
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StorageError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.key_for(hash))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.as_service_error()
                    .map(|s| s.is_not_found())
                    .unwrap_or(false)
                {
                    Ok(false)
                } else {
                    Err(StorageError::Backend(e.to_string()))
                }
            }
        }
    }

    fn partition_id(&self) -> PartitionId {
        self.partition_id
    }
}
