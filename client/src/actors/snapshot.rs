// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::snapshot;

use engine::vault::{Key, ReadResult};

use engine::store::Cache;

use crate::{
    actors::{InternalMsg, SHResults},
    client::Client,
    line_error,
    snapshot::{Snapshot, SnapshotState},
    utils::StatusMessage,
    ClientId, Provider, VaultId,
};

use std::collections::HashMap;

/// Messages used for the Snapshot Actor.
#[derive(Clone, Debug)]
pub enum SMsg {
    WriteSnapshotAll {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        data: (
            Client,
            HashMap<VaultId, Key<Provider>>,
            HashMap<Key<Provider>, Vec<ReadResult>>,
            Cache<Vec<u8>, Vec<u8>>,
        ),
        id: ClientId,
        is_final: bool,
    },
    ReadFromSnapshot {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        id: ClientId,
        fid: Option<ClientId>,
    },
}

/// Actor Factory for the Snapshot.
impl ActorFactory for Snapshot {
    fn create() -> Self {
        Snapshot::new(SnapshotState::default())
    }
}

impl Actor for Snapshot {
    type Msg = SMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<SMsg> for Snapshot {
    type Msg = SMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        match msg {
            SMsg::WriteSnapshotAll {
                key,
                filename,
                path,
                data,
                id,
                is_final,
            } => {
                self.state.add_data(id, data);

                if is_final {
                    self.clone()
                        .write_to_snapshot(filename.as_deref(), path.as_deref(), key)
                        .expect(line_error!());

                    self.state = SnapshotState::default();

                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnWriteSnap(StatusMessage::OK), None)
                        .expect(line_error!());
                } else {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnWriteSnap(StatusMessage::OK), None)
                        .expect(line_error!());
                }
            }
            SMsg::ReadFromSnapshot {
                key,
                filename,
                path,
                id,
                fid,
            } => {
                let id_str: String = id.into();
                let internal = ctx.select(&format!("/user/internal-{}/", id_str)).expect(line_error!());
                let cid = if let Some(fid) = fid { fid } else { id };

                if self.has_data(cid) {
                    let data = self.get_state(cid);

                    internal.try_tell(InternalMsg::ReloadData(Box::new(data), StatusMessage::OK), sender);
                } else {
                    match Snapshot::read_from_snapshot(filename.as_deref(), path.as_deref(), key) {
                        Ok(mut snapshot) => {
                            let data = snapshot.get_state(cid);

                            *self = snapshot;

                            internal.try_tell(InternalMsg::ReloadData(Box::new(data), StatusMessage::OK), sender);
                        }
                        Err(e) => {
                            sender
                                .as_ref()
                                .expect(line_error!())
                                .try_tell(
                                    SHResults::ReturnReadSnap(StatusMessage::Error(format!(
                                        "{}, Unable to read snapshot. Please try another password.",
                                        e
                                    ))),
                                    None,
                                )
                                .expect(line_error!());
                        }
                    }
                };
            }
        }
    }
}
