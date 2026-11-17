//! `HttpBackend` — talks to any HTTP(S) server exposing bitchain's simple
//! per-hash object contract: `GET/PUT/HEAD <base_url>/<partition_hex>/<hash_hex>`.
//! This is the shape a Refraction server (or any static file host serving a
//! pre-populated bucket) needs to speak to interoperate. Object bodies use
//! the same `[codec_byte][payload]` framing as `S3Backend`.

use crate::addressing::{Hash, PartitionId};
use crate::backend::AsyncImmutableStore;
use crate::error::StorageError;
use crate::store::packfile::{decode, encode, Codec};

pub struct HttpBackend {
    client: reqwest::Client,
    base_url: String,
    partition_id: PartitionId,
}

impl HttpBackend {
    pub fn new(base_url: impl Into<String>, partition_id: PartitionId) -> Self {
        HttpBackend {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            partition_id,
        }
    }

    fn url_for(&self, hash: &Hash) -> String {
        format!(
            "{}/{}/{}",
            self.base_url.trim_end_matches('/'),
            self.partition_id.to_hex(),
            hash.to_hex()
        )
    }
}

#[async_trait::async_trait]
impl AsyncImmutableStore for HttpBackend {
    async fn get(&self, hash: &Hash) -> Result<Vec<u8>, StorageError> {
        let resp = self
            .client
            .get(self.url_for(hash))
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(StorageError::NotFound(hash.to_hex()));
        }
        if !resp.status().is_success() {
            return Err(StorageError::Backend(format!(
                "GET {} returned {}",
                self.url_for(hash),
                resp.status()
            )));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        if body.is_empty() {
            return Err(StorageError::Backend("empty response body".into()));
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
            return Ok(hash);
        }
        let (codec, payload) = encode(data)?;
        let mut body = Vec::with_capacity(1 + payload.len());
        body.push(codec as u8);
        body.extend_from_slice(&payload);

        let resp = self
            .client
            .put(self.url_for(&hash))
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Backend(format!(
                "PUT {} returned {}",
                self.url_for(&hash),
                resp.status()
            )));
        }
        Ok(hash)
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StorageError> {
        let resp = self
            .client
            .head(self.url_for(hash))
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(resp.status().is_success())
    }

    fn partition_id(&self) -> PartitionId {
        self.partition_id
    }
}
