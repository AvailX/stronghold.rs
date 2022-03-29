// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This module contains the  Stronghold snapshot interface.
//! A snapshot is a current view of the memory state inside all [`Client`]s

#![allow(clippy::type_complexity)]

use crypto::keys::x25519;
use engine::{
    snapshot::{
        self, read, read_from as read_from_file, write, write_to as write_to_file, Key, ReadError as EngineReadError,
        WriteError as EngineWriteError,
    },
    store::Cache,
    vault::{view::Record, BlobId, BoxProvider, ClientId, DbView, Key as PKey, RecordHint, RecordId, VaultId},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::Infallible,
    ops::Deref,
    path::{Path, PathBuf},
};
use stronghold_utils::random;

use crate::{
    procedures::{DeriveSecret, X25519DiffieHellman},
    sync::{self, KeyProvider, SyncClients, SyncClientsConfig, SyncSnapshots, SyncSnapshotsConfig},
    KeyStore, Location, Provider, SnapshotError,
};

type EncryptedClientState = (Vec<u8>, Cache<Vec<u8>, Vec<u8>>);

pub type ClientState = (
    HashMap<VaultId, PKey<Provider>>,
    DbView<Provider>,
    Cache<Vec<u8>, Vec<u8>>,
);

impl<'a> SyncClients<'a> for ClientState {
    type Db = &'a DbView<Provider>;

    fn get_db(&'a self) -> Self::Db {
        &self.1
    }

    fn get_key_provider(&'a self) -> KeyProvider<'a> {
        KeyProvider::KeyMap(&self.0)
    }
}

/// Wrapper for the [`SnapshotState`] data structure.
#[derive(Default)]
pub struct Snapshot {
    // Keys for vaults in db and for the encrypted client states.
    keystore: KeyStore<Provider>,
    // Db with snapshot keys.
    db: DbView<Provider>,
    // Loaded snapshot states with each client state separately encrypted.
    states: HashMap<ClientId, EncryptedClientState>,
}

/// Data structure that is written to the snapshot.
#[derive(Deserialize, Serialize, Default)]
pub struct SnapshotState(pub(crate) HashMap<ClientId, ClientState>);

// impl Default for Snapshot {
//     fn default() -> Self {
//         Snapshot {
//             keystore: KeyStore::default(),
//             db: DbView::default(),
//             states: HashMap::default(),
//         }
//     }
// }

/// A handle for snapshot file locations.
///
/// # Examples
/// ```no_run
/// use iota_stronghold_new::SnapshotPath;
///
/// // set path to a known location for a snapshot file
/// let named = SnapshotPath::named("snapshot-file");
/// // set path to an absolute location for a snapshot file
/// let path = SnapshotPath::from_path("/path/to/snapshot/file");
/// ```
#[derive(Clone, Debug)]
pub struct SnapshotPath {
    /// The absolute path to a snapshot file location
    path: PathBuf,
}

impl SnapshotPath {
    /// Creates a [`SnapshotPath`] by a known location for [`Snapshot`] files.
    /// That is the home directory in most cases.
    ///
    /// # Example
    pub fn named<P>(name: P) -> Self
    where
        P: AsRef<Path>,
    {
        assert!(name.as_ref().is_relative());
        // assert!(name.as_ref().is_file());
        assert!(engine::snapshot::files::home_dir().is_ok());

        let path = engine::snapshot::files::home_dir().unwrap();

        Self { path: path.join(name) }
    }

    /// Creates a [`SnapshotPath`] by an absolute path for [`Snapshot`] files.
    ///
    /// # Example
    /// ```
    /// ```
    pub fn from_path<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        assert!(path.as_ref().is_absolute());

        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Returns [`Self`] as Path
    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Debug)]
pub enum UseKey {
    Key(snapshot::Key),
    Stored(Location),
}

impl Snapshot {
    /// Creates a new [`Snapshot`] from a buffer of [`SnapshotState`] state.
    pub fn from_state(
        state: SnapshotState,
        snapshot_key: Key,
        write_key: Option<(VaultId, RecordId)>,
    ) -> Result<Self, SnapshotError> {
        let mut snapshot = Snapshot::default();
        if let Some((vid, rid)) = write_key {
            snapshot.store_snapshot_key(snapshot_key, vid, rid)?;
        }
        for (client_id, state) in state.0 {
            snapshot.add_data(client_id, state)?;
        }
        Ok(snapshot)
    }

    /// Gets the state component parts as a tuple.
    pub fn get_snapshot_state(&self) -> Result<SnapshotState, SnapshotError> {
        let mut state = SnapshotState::default();
        let ids: Vec<ClientId> = self.states.keys().cloned().collect();
        for client_id in ids {
            let client_state = self.get_state(client_id)?;
            state.0.insert(client_id, client_state);
            // match self.get_state(client_id) {
            //     Ok(client_state) => {

            //     }
            //     Err(_) => {
            //         // File not present, could not retrieve previous state
            //     }
            // };
        }
        Ok(state)
    }

    /// Gets the state component parts as a tuple.
    pub fn get_state(&self, id: ClientId) -> Result<ClientState, SnapshotError> {
        let vid = VaultId(id.0);
        let ((encrypted, store), key) = match self
            .states
            .get(&id)
            .and_then(|state| self.keystore.get_key(vid).map(|pkey| (state, pkey)))
            .and_then(|(state, pkey)| {
                let k = &pkey.key;
                k.borrow().deref().try_into().ok().map(|k| (state, k))
            }) {
            Some(t) => t,
            None => return Ok((HashMap::default(), DbView::default(), Cache::default())),
        };
        let decrypted = read(&mut encrypted.as_slice(), &key, &[])?;
        let (keys, db) = bincode::deserialize(&decrypted)?;
        Ok((keys, db, store.clone()))
    }

    /// Checks to see if the [`ClientId`] exists in the snapshot hashmap.
    pub fn has_data(&self, cid: ClientId) -> bool {
        self.states.contains_key(&cid)
    }

    /// Reads state from the specified named snapshot or the specified path
    /// TODO: Add associated data.
    pub fn read_from_snapshot(
        snapshot_path: &SnapshotPath,
        key: Key,
        write_key: Option<(VaultId, RecordId)>,
    ) -> Result<Self, SnapshotError> {
        // let data = match path {
        //     Some(p) => read_from_file(p, &key, &[])?,
        //     None => read_from_file(&snapshot::files::get_path(name)?, &key, &[])?,
        // };

        let data = read_from_file(snapshot_path.as_path(), &key, &[])?;

        let state = bincode::deserialize(&data)?;
        Snapshot::from_state(state, key, write_key)
    }

    /// Writes state to the specified named snapshot or the specified path
    /// TODO: Add associated data.
    /// TODO: This should be split into two functions :
    ///   - named_mut()
    ///   - path_
    pub fn write_to_snapshot(
        &self,
        // name: Option<&str>,
        // path: Option<&Path>,
        snapshot_path: &SnapshotPath,
        use_key: UseKey,
    ) -> Result<(), SnapshotError> {
        let state = self.get_snapshot_state()?;
        let data = bincode::serialize(&state)?;

        let key = match use_key {
            UseKey::Key(k) => k,
            UseKey::Stored(loc) => {
                let (vid, rid) = loc.resolve();
                let pkey = self.keystore.get_key(vid).ok_or(SnapshotError::SnapshotKey(vid, rid))?;
                let mut data = Vec::new();
                self.db
                    .get_guard::<Infallible, _>(&pkey, vid, rid, |guarded_data| {
                        let guarded_data = guarded_data.borrow();
                        data.extend_from_slice(&*guarded_data);
                        Ok(())
                    })
                    .map_err(|e| SnapshotError::Vault(format!("{}", e)))?;
                data.try_into().map_err(|_| SnapshotError::SnapshotKey(vid, rid))?
            }
        };

        // // TODO: This is a hack and probably should be removed when we add proper error handling.
        // let f = move || match path {
        //     Some(p) => write_to_file(&data, p, &key, &[]),
        //     None => write_to_file(&data, &snapshot::files::get_path(name)?, &key, &[]),
        // };

        // match f() {
        //     Ok(()) => Ok(()),
        //     Err(_) => f().map_err(|e| e.into()),
        // }

        write_to_file(&data, snapshot_path.as_path(), &key, &[]).map_err(|e| e.into())
    }

    /// Adds data to the snapshot state hashmap.
    pub fn add_data(
        &mut self,
        id: ClientId,
        (keys, db, store): (
            HashMap<VaultId, PKey<Provider>>,
            DbView<Provider>,
            Cache<Vec<u8>, Vec<u8>>,
        ),
    ) -> Result<(), SnapshotError> {
        let bytes = bincode::serialize(&(keys, db))?;
        let vault_id = VaultId(id.0);
        let key: snapshot::Key = random::random();
        let mut buffer = Vec::new();
        write(&bytes, &mut buffer, &key, &[])?;
        let pkey = PKey::load(key.into()).expect("Provider::box_key_len == KEY_SIZE == 32");
        self.keystore
            .insert_key(vault_id, pkey)
            .map_err(|e| SnapshotError::Inner(e.to_string()))?;
        self.states.insert(id, (buffer, store));
        Ok(())
    }

    /// Adds data to the snapshot state hashmap.
    pub fn store_snapshot_key(
        &mut self,
        snapshot_key: snapshot::Key,
        vault_id: VaultId,
        record_id: RecordId,
    ) -> Result<(), SnapshotError> {
        // this should return an error
        let key = self.keystore.create_key(vault_id).expect("Could not create key");
        self.db
            .write(
                &key,
                vault_id,
                record_id,
                &snapshot_key,
                RecordHint::new("").expect("0 <= 24"),
            )
            .map_err(|e| SnapshotError::Vault(format!("{}", e)))?;
        Ok(())
    }

    /// Merge another state into the currently loaded snapshot.
    pub fn merge_state(&mut self, mut state: SnapshotState, config: SyncSnapshotsConfig) -> Result<(), SnapshotError> {
        let hierarchy = state.get_hierarchy(config.select_clients.clone());
        let diff = self.get_diff(hierarchy, &config);
        let exported = state.export_entries(diff);
        let old_keys = exported
            .keys()
            .map(|cid| (*cid, state.0.remove(cid).unwrap().0))
            .collect();
        self.import_records(exported, &old_keys, &config);
        Ok(())
    }

    /// Deserialize, decompress and decrypt a state received from a remote peer and merge
    /// it into the local sate.
    ///
    /// The snapshot is decrypted with a shared key that is created in a handshake between
    /// the local secret key at `local_sk` and the remote public key `remote_pk`.
    pub fn import_from_serialized_state(
        &mut self,
        bytes: Vec<u8>,
        local_sk: Location,
        remote_pk: x25519::PublicKey,
        config: SyncSnapshotsConfig,
    ) -> Result<(), SnapshotError> {
        let (vid, rid) = local_sk.resolve();
        let vault_key = self.keystore.get_key(vid).unwrap();

        let decrypted = &mut Vec::new();
        self.db
            .get_guard::<SnapshotError, _>(&vault_key, vid, rid, |guard| {
                let sk = x25519::SecretKey::try_from_slice(&*guard.borrow())?;
                let shared_key = sk.diffie_hellman(&remote_pk);
                let pt = engine::snapshot::read(&mut bytes.as_slice(), shared_key.as_bytes(), &[])?;
                *decrypted = pt;
                Ok(())
            })
            .unwrap();
        let data = engine::snapshot::decompress(decrypted).unwrap();
        let state: SnapshotState = bincode::deserialize(&data).unwrap();
        self.merge_state(state, config)
    }

    /// Export the given hierarchy from the loaded state to a blank `SnapshotState`.
    /// Serialize, compress and encrypt the state so it can be sent to a remote peer.
    ///
    /// The snapshot is encrypted with a shared key that is created in a handshake between
    /// the local secret key at `local_sk` and the remote public key `remote_pk`.
    pub fn export_to_serialized_state(
        &self,
        select: HashMap<ClientId, HashMap<VaultId, Vec<RecordId>>>,
        remote_pk: x25519::PublicKey,
    ) -> Result<(x25519::PublicKey, Vec<u8>), SnapshotError> {
        let mut blank = SnapshotState::default();

        let mut old_keys = HashMap::new();
        let exported = select
            .into_iter()
            .filter_map(|(cid, select)| {
                let state = self.get_state(cid).unwrap();
                let exported = state.export_entries(select);
                if exported.is_empty() {
                    return None;
                }
                old_keys.insert(cid, state.0);
                Some((cid, exported))
            })
            .collect();

        blank.import_records(exported, &old_keys, &SyncSnapshotsConfig::default());
        let data = bincode::serialize(&blank).unwrap();
        let compressed_plain = engine::snapshot::compress(data.as_slice());
        let mut buffer = Vec::new();

        // Perform a handshake with the remote's public key and an ephemeral local key to create the snapshot key.
        let sk = x25519::SecretKey::generate().unwrap();
        let shared_key = sk.diffie_hellman(&remote_pk);
        let pk = sk.public_key();
        engine::snapshot::write(&compressed_plain, &mut buffer, shared_key.as_bytes(), &[])?;
        Ok((pk, buffer))
    }
}

impl SyncSnapshots for Snapshot {
    fn clients(&self) -> Vec<ClientId> {
        self.states.keys().cloned().collect()
    }

    fn get_from_state<F, T>(&self, cid: ClientId, f: F) -> T
    where
        F: FnOnce(Option<&ClientState>) -> T,
    {
        let state = self.get_state(cid).unwrap();
        f(Some(&state))
    }

    fn update_state<F, T>(&mut self, cid: ClientId, f: F)
    where
        F: FnOnce(&mut ClientState) -> T,
    {
        let mut state = self.get_state(cid).unwrap();
        f(&mut state);
        self.add_data(cid, state).unwrap();
    }
}

impl SyncSnapshots for SnapshotState {
    fn clients(&self) -> Vec<ClientId> {
        self.0.keys().cloned().collect()
    }

    fn get_from_state<F, T>(&self, cid: ClientId, f: F) -> T
    where
        F: FnOnce(Option<&ClientState>) -> T,
    {
        let state = self.0.get(&cid);
        f(state)
    }

    fn update_state<F, T>(&mut self, cid: ClientId, f: F)
    where
        F: FnOnce(&mut ClientState) -> T,
    {
        let state = self.0.entry(cid).or_default();
        f(state);
    }
}

impl From<bincode::Error> for SnapshotError {
    fn from(e: bincode::Error) -> Self {
        SnapshotError::CorruptedContent(format!("bincode error: {}", e))
    }
}

impl From<<Provider as BoxProvider>::Error> for SnapshotError {
    fn from(e: <Provider as BoxProvider>::Error) -> Self {
        SnapshotError::Provider(format!("{:?}", e))
    }
}

impl From<EngineReadError> for SnapshotError {
    fn from(e: EngineReadError) -> Self {
        match e {
            EngineReadError::CorruptedContent(reason) => SnapshotError::CorruptedContent(reason),
            EngineReadError::InvalidFile => SnapshotError::InvalidFile("Not a Snapshot.".into()),
            EngineReadError::Io(io) => SnapshotError::Io(io),
            EngineReadError::UnsupportedVersion { expected, found } => SnapshotError::InvalidFile(format!(
                "Unsupported version: expected {:?}, found {:?}.",
                expected, found
            )),
        }
    }
}

impl From<EngineWriteError> for SnapshotError {
    fn from(e: EngineWriteError) -> Self {
        match e {
            EngineWriteError::Io(io) => SnapshotError::Io(io),
            EngineWriteError::CorruptedData(e) => SnapshotError::CorruptedContent(e),
            EngineWriteError::GenerateRandom(_) => SnapshotError::Io(std::io::ErrorKind::Other.into()),
        }
    }
}
