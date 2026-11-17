//! `LocalBackend` — the default, no-network backend. A thin async wrapper
//! over [`crate::store::PartitionStore`]; all packfile/fragmentation logic
//! lives once, in [`crate::store`]/[`crate::fragment`], and this module
//! never reimplements it.

use crate::addressing::{Hash, PartitionId};
use crate::backend::AsyncImmutableStore;
use crate::error::StorageError;
use crate::store::{ImmutableStore, PartitionStore};
use async_trait::async_trait;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct LocalBackend {
    store: Arc<Mutex<PartitionStore>>,
    partition_id: PartitionId,
}

impl LocalBackend {
    pub fn open(store_root: &Path, partition_id: PartitionId) -> Result<Self, StorageError> {
        let store = PartitionStore::open(store_root, partition_id)?;
        Ok(LocalBackend {
            store: Arc::new(Mutex::new(store)),
            partition_id,
        })
    }
}

fn join_err<T>(e: tokio::task::JoinError) -> Result<T, StorageError> {
    Err(StorageError::Backend(format!(
        "local backend task panicked: {e}"
    )))
}

#[async_trait]
impl AsyncImmutableStore for LocalBackend {
    async fn get(&self, hash: &Hash) -> Result<Vec<u8>, StorageError> {
        let store = self.store.clone();
        let hash = *hash;
        match tokio::task::spawn_blocking(move || {
            let store = store.lock().expect("local backend mutex poisoned");
            store.get(&hash)
        })
        .await
        {
            Ok(result) => result,
            Err(e) => join_err(e),
        }
    }

    async fn put(&self, data: &[u8]) -> Result<Hash, StorageError> {
        let store = self.store.clone();
        let data = data.to_vec();
        match tokio::task::spawn_blocking(move || {
            let mut store = store.lock().expect("local backend mutex poisoned");
            store.put(&data)
        })
        .await
        {
            Ok(result) => result,
            Err(e) => join_err(e),
        }
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StorageError> {
        let store = self.store.clone();
        let hash = *hash;
        match tokio::task::spawn_blocking(move || {
            let store = store.lock().expect("local backend mutex poisoned");
            store.has(&hash)
        })
        .await
        {
            Ok(result) => Ok(result),
            Err(e) => join_err(e),
        }
    }

    fn partition_id(&self) -> PartitionId {
        self.partition_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition::{EncryptionMode, PartitionSpec, RetentionClass, Subject, SubjectKind};
    use tempfile::tempdir;

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let dir = tempdir().unwrap();
        let partition_id = PartitionId::for_person("storage-kit-local-test");
        let spec = PartitionSpec {
            subject: Subject {
                kind: SubjectKind::Person,
                id: "storage-kit-local-test".to_string(),
            },
            retention_class: RetentionClass::Standard,
            encryption_mode: EncryptionMode::Plaintext,
            label: None,
        };
        // `LocalBackend::open` wraps `PartitionStore::open`, which no
        // longer provisions on first use — provision first, same as any
        // other caller now must.
        PartitionStore::create(dir.path(), partition_id, spec).unwrap();
        let backend = LocalBackend::open(dir.path(), partition_id).unwrap();

        let hash = backend.put(b"local backend round trip").await.unwrap();
        assert!(backend.has(&hash).await.unwrap());
        let back = backend.get(&hash).await.unwrap();
        assert_eq!(back, b"local backend round trip");
        assert_eq!(backend.partition_id(), partition_id);
    }
}
