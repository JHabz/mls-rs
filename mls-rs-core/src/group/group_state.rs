// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::error::IntoAnyError;
#[cfg(mls_build_async)]
use alloc::boxed::Box;
use alloc::vec::Vec;
use mls_rs_codec::{MlsDecode, MlsEncode};

/// Generic representation of a group's state.
pub trait GroupState {
    /// A unique group identifier.
    fn id(&self) -> Vec<u8>;
}

/// Generic representation of a prior epoch.
pub trait EpochRecord {
    /// A unique epoch identifier within a particular group.
    fn id(&self) -> u64;
}

/// Storage that can persist and reload a group state.
///
/// A group state is recorded as a combination of the current state
/// (represented by the [`GroupState`] trait) and some number of prior
/// group states (represented by the [`EpochRecord`] trait).
/// This trait implements reading and writing group data as requested by the protocol
/// implementation.
///
/// # Cleaning up records
///
/// Group state will not be purged when the local member is removed from the
/// group. It is up to the implementer of this trait to provide a mechanism
/// to delete records that can be used by an application.
///
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
pub trait GroupStateStorage: Send + Sync {
    type Error: IntoAnyError;

    /// Fetch a group state from storage.
    async fn state<'a, T>(&self, group_id: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: GroupState + Codec<'a>;

    /// Lazy load cached epoch data from a particular group.
    async fn epoch<'a, T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: EpochRecord + Codec<'a>;

    /// Write pending state updates.
    ///
    /// The group id that this update belongs to can be retrieved with
    /// [`GroupState::id`]. Prior epoch id values can be retrieved with
    /// [`EpochRecord::id`].
    ///
    /// The protocol implementation handles managing the max size of a prior epoch
    /// cache and the deleting of prior states based on group activity.
    /// The maximum number of prior epochs that will be stored is controlled by the
    /// `Preferences::max_epoch_retention` function in `mls_rs`.
    /// value. Requested deletes are communicated by the `delete_epoch_under`
    /// parameter being set to `Some`.
    ///
    /// # Warning
    ///
    /// It is important to consider error recovery when creating an implementation
    /// of this trait. Calls to [`write`](GroupStateStorage::write) should
    /// optimally be a single atomic transaction in order to avoid partial writes
    /// that may corrupt the group state.
    async fn write<'a, ST, ET>(
        &mut self,
        state: ST,
        epoch_inserts: Vec<ET>,
        epoch_updates: Vec<ET>,
    ) -> Result<(), Self::Error>
    where
        ST: GroupState + Codec<'a> + Send + Sync,
        ET: EpochRecord + Codec<'a> + Send + Sync;

    /// The [`EpochRecord::id`] value that is associated with a stored
    /// prior epoch for a particular group.
    async fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error>;
}

#[cfg(feature = "serde")]
pub trait Codec<'a>: MlsEncode + serde::Serialize + MlsDecode + serde::Deserialize<'a> {}

#[cfg(not(feature = "serde"))]
pub trait Codec<'a>: MlsEncode + MlsDecode {}
