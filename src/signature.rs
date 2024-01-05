// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::Error;

use dusk_bls12_381::{G1Affine, G1Projective};
use dusk_bytes::Serializable;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// A BLS signature.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Signature(pub(crate) G1Affine);

impl Signature {
    /// Aggregate a set of signatures by simply adding up the points.
    pub fn aggregate(&self, sigs: &[Signature]) -> Self {
        Self(
            sigs.iter().fold(self.0, |acc, sig| {
                (acc + G1Projective::from(sig.0)).into()
            }),
        )
    }
}

impl Serializable<48> for Signature {
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Error> {
        Ok(Self(G1Affine::from_bytes(bytes)?))
    }
}
