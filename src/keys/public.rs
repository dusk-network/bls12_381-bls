// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::hash::{h0, h1};
use crate::{Error, SecretKey, Signature};

use dusk_bls12_381::G2Affine;
use dusk_bytes::{Error as DuskBytesError, Serializable};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// A BLS public key, holding a BLS12-381 G2 element inside.
/// The G2 element is constructed by multiplying a [`SecretKey`]
/// by `g2` (the base point of the G2 group).
/// Can be used for signature verification.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct PublicKey(pub(crate) G2Affine);

impl Serializable<96> for PublicKey {
    type Error = DuskBytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Ok(Self(G2Affine::from_bytes(bytes)?))
    }
}

impl From<&SecretKey> for PublicKey {
    /// Generates a new [`PublicKey`] from a [`SecretKey`].
    /// pk = g_2 * sk
    fn from(sk: &SecretKey) -> Self {
        let g_2 = G2Affine::generator();
        let gx = g_2 * sk.0;

        Self(gx.into())
    }
}

impl PublicKey {
    /// Verify a [`Signature`] by comparing the results of the two pairing
    /// operations: e(sig, g_2) == e(Hₒ(m), pk).
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> Result<(), Error> {
        let h0m = h0(msg);
        let p1 = dusk_bls12_381::pairing(&sig.0, &G2Affine::generator());
        let p2 = dusk_bls12_381::pairing(&h0m, &self.0);

        if p1.eq(&p2) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Return pk * t, where t is H_(pk).
    pub fn pk_t(&self) -> G2Affine {
        let t = h1(self);
        let gx = self.0 * t;
        gx.into()
    }

    /// Raw bytes representation
    ///
    /// The intended usage of this function is for trusted sets of data where
    /// performance is critical.
    ///
    /// For secure serialization, check `to_bytes`
    pub fn to_raw_bytes(&self) -> [u8; G2Affine::RAW_SIZE] {
        self.0.to_raw_bytes()
    }

    /// Create a `PublicKey` from a set of bytes created by
    /// `PublicKey::to_raw_bytes`.
    ///
    /// # Safety
    ///
    /// No check is performed and no constant time is granted. The expected
    /// usage of this function is for trusted bytes where performance is
    /// critical.
    ///
    /// For secure serialization, check `from_bytes`
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        Self(G2Affine::from_slice_unchecked(bytes))
    }

    /// Returns true if the inner point is free of an $h$-torsion component, and
    /// so it exists within the $q$-order subgroup $\mathbb{G}_2$. This
    /// should always return true unless an "unchecked" API was used.
    pub fn is_torsion_free(&self) -> bool {
        self.0.is_torsion_free().into()
    }

    /// Returns true if the inner point is on the curve. This should always
    /// return true unless an "unchecked" API was used.
    pub fn is_on_curve(&self) -> bool {
        self.0.is_on_curve().into()
    }

    /// Returns true if the inner point is the identity (the point at infinity).
    pub fn is_identity(&self) -> bool {
        self.0.is_identity().into()
    }

    /// Returns true if the inner point is valid according to certain criteria.
    ///
    /// A [`PublicKey`] is considered valid if its inner point meets the
    /// following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        self.is_torsion_free() && self.is_on_curve() && !self.is_identity()
    }
}
