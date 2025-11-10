// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::hash::{h0, h1};
use crate::signatures::is_valid as is_valid_sig;
use crate::{Error, MultisigSignature, SecretKey, Signature};

use dusk_bls12_381::{G1Affine, G2Affine, G2Prepared, G2Projective};
use dusk_bytes::{Error as DuskBytesError, Serializable};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
pub struct PublicKey(G2Affine);

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
        verify(&self.0, &sig.0, msg)
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

    /// Returns true if the inner point is valid according to certain criteria.
    ///
    /// A [`PublicKey`] is considered valid if its inner point meets the
    /// following conditions:
    /// 1. It is free of an $h$-torsion component and exists within the
    ///    $q$-order subgroup $\mathbb{G}_2$.
    /// 2. It is on the curve.
    /// 3. It is not the identity.
    pub fn is_valid(&self) -> bool {
        is_valid(&self.0)
    }
}

fn verify(key: &G2Affine, sig: &G1Affine, msg: &[u8]) -> Result<(), Error> {
    if !is_valid(key) || !is_valid_sig(sig) {
        return Err(Error::InvalidPoint);
    }
    let h0m = h0(msg);

    let p = dusk_bls12_381::multi_miller_loop(&[
        (sig, &G2Prepared::from(G2Affine::generator())),
        (&-h0m, &G2Prepared::from(*key)),
    ])
    .final_exponentiation();

    if p.eq(&dusk_bls12_381::Gt::identity()) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

fn is_valid(key: &G2Affine) -> bool {
    let is_identity: bool = key.is_identity().into();
    key.is_torsion_free().into() && key.is_on_curve().into() && !is_identity
}

/// Aggregated form of a BLS public key.
/// The public keys are aggregated in a rogue-key attack
/// resistant manner, by using the hash function defined
/// in the modified version of BLS.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct MultisigPublicKey(G2Affine);

impl Serializable<96> for MultisigPublicKey {
    type Error = DuskBytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Ok(MultisigPublicKey(G2Affine::from_bytes(bytes)?))
    }
}

impl MultisigPublicKey {
    /// Aggregate a set of [`PublicKey`] into a [`MultisigPublicKey`].
    ///
    /// # Errors
    ///
    /// The aggregation errors when an empty slice is passed, or one of the
    /// [`PublicKey`]s is made of the identity or an otherwise invalid point.
    pub fn aggregate(pks: &[PublicKey]) -> Result<Self, Error> {
        if pks.is_empty() {
            return Err(Error::NoKeysProvided);
        }

        #[cfg(not(feature = "parallel"))]
        let valid_iter = pks.iter();
        #[cfg(feature = "parallel")]
        let valid_iter = pks.par_iter();

        #[cfg(not(feature = "parallel"))]
        let pks_valid =
            valid_iter.fold(true, |acc, next| acc & next.is_valid());
        #[cfg(feature = "parallel")]
        let pks_valid = valid_iter
            .map(PublicKey::is_valid)
            .reduce(|| true, |acc, next| acc & next);

        if !pks_valid {
            return Err(Error::InvalidPoint);
        }

        #[cfg(not(feature = "parallel"))]
        let sum_iter = pks.iter();
        #[cfg(feature = "parallel")]
        let sum_iter = pks.par_iter();

        let sum: G2Projective =
            sum_iter.map(|pk| G2Projective::from(pk.pk_t())).sum();

        Ok(Self(sum.into()))
    }

    /// Verify a [`MultisigSignature`].
    /// Wrapper function for PublicKey.verify.
    /// Currently, this function only supports batched signature verification
    /// for the same message. Distinct messages are not supported.
    pub fn verify(
        &self,
        sig: &MultisigSignature,
        msg: &[u8],
    ) -> Result<(), Error> {
        verify(&self.0, &sig.0, msg)
    }

    /// Raw bytes representation
    ///
    /// The intended usage of this function is for trusted sets of data where
    /// performance is critical.
    ///
    /// For secure serialization, check `to_bytes`
    pub fn to_raw_bytes(&self) -> [u8; dusk_bls12_381::G2Affine::RAW_SIZE] {
        self.0.to_raw_bytes()
    }

    /// Create a `MultisigPublicKey` from a set of bytes created by
    /// `MultisigPublicKey::to_raw_bytes`.
    ///
    /// # Safety
    ///
    /// No check is performed and no constant time is granted. The expected
    /// usage of this function is for trusted bytes where performance is
    /// critical.
    ///
    /// For secure serialization, check `from_bytes`
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        MultisigPublicKey(G2Affine::from_slice_unchecked(bytes))
    }
}
