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

/// A BLS signature, in the single-signature scheme.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Signature(pub(crate) G1Affine);

impl Signature {
    /// Returns true if the inner point is valid according to certain criteria.
    ///
    /// A [`Signature`] is considered valid if its inner point meets the
    /// following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        is_valid(&self.0)
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

pub(crate) fn is_valid(sig: &G1Affine) -> bool {
    let is_identity: bool = sig.is_identity().into();
    sig.is_torsion_free().into() && sig.is_on_curve().into() && !is_identity
}

/// A BLS signature, in the multi-signature scheme.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct MultisigSignature(pub(crate) G1Affine);

impl MultisigSignature {
    /// Aggregate a set of signatures by adding up the points.
    pub fn aggregate(&self, sigs: &[MultisigSignature]) -> Self {
        Self(
            sigs.iter().fold(self.0, |acc, sig| {
                (acc + G1Projective::from(sig.0)).into()
            }),
        )
    }

    /// Returns true if the inner point is valid according to certain criteria.
    ///
    /// A [`MultisigSignature`] is considered valid if its inner point meets the
    /// following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        is_valid(&self.0)
    }
}

impl Serializable<48> for MultisigSignature {
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Error> {
        Ok(Self(G1Affine::from_bytes(bytes)?))
    }
}
