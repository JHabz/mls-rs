// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use mls_rs_codec::MlsEncode;
use mls_rs_core::group::Codec;
pub use mls_rs_core::group::{EpochRecord, GroupState};

use crate::group::snapshot::Snapshot;

#[cfg(feature = "prior_epoch")]
use crate::group::epoch::PriorEpoch;

#[cfg(feature = "prior_epoch")]
impl EpochRecord for PriorEpoch {
    fn id(&self) -> u64 {
        self.epoch_id()
    }
}

#[cfg(feature = "prior_epoch")]
impl<'a> Codec<'a> for PriorEpoch {}

impl GroupState for Snapshot {
    fn id(&self) -> Vec<u8> {
        self.group_id().to_vec()
    }
}

impl<'a> Codec<'a> for Snapshot {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EpochData {
    pub(crate) id: u64,
    pub(crate) data: Vec<u8>,
}

impl EpochData {
    pub(crate) fn new<T>(value: T) -> Result<Self, mls_rs_codec::Error>
    where
        T: MlsEncode + EpochRecord,
    {
        Ok(Self {
            id: value.id(),
            data: value.mls_encode_to_vec()?,
        })
    }
}
