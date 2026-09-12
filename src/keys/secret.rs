// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::hash::{h0, h0_multisig_v3, h0_single_v3, h1};
#[cfg(feature = "insecure-v1-signing")]
use crate::hash::{h0_insecure_point, h1_insecure};
use crate::{MultisigSignature, PublicKey, Signature};

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error as DuskBytesError, Serializable};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// A BLS secret key, holding a BLS12-381 scalar inside.
/// Can be used for signing messages.
///
/// ## Safety
///
/// To ensure that no secret information lingers in memory after the variable
/// goes out of scope, we advice calling `zeroize` before the variable goes out
/// of scope.
///
/// ## Examples
///
/// Generate a random `SecretKey`:
/// ```
/// use bls12_381_bls::SecretKey;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use zeroize::Zeroize;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let mut sk = SecretKey::random(&mut rng);
///
/// // do something with the sk
///
/// sk.zeroize();
/// ```
#[derive(Default, Clone, Debug, Eq, PartialEq, Zeroize)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SecretKey(pub(crate) BlsScalar);

impl From<BlsScalar> for SecretKey {
    fn from(s: BlsScalar) -> SecretKey {
        SecretKey(s)
    }
}

impl From<&BlsScalar> for SecretKey {
    fn from(s: &BlsScalar) -> SecretKey {
        SecretKey(*s)
    }
}

impl AsRef<BlsScalar> for SecretKey {
    fn as_ref(&self) -> &BlsScalar {
        &self.0
    }
}

impl SecretKey {
    /// Generates a new random [`SecretKey`] from a [`BlsScalar].
    pub fn random<T>(rand: &mut T) -> Self
    where
        T: RngCore + CryptoRng,
    {
        Self(BlsScalar::random(&mut *rand))
    }
}

impl Serializable<32> for SecretKey {
    type Error = DuskBytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let secret_key = match BlsScalar::from_bytes(bytes).into() {
            Some(sk) => sk,
            None => return Err(DuskBytesError::InvalidData),
        };
        Ok(Self(secret_key))
    }
}

impl SecretKey {
    /// Sign a message using the default single-signature behavior.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        // Hash message
        let h = h0(msg);

        // Multiply point by sk
        let e = h * self.0;
        Signature(e.into())
    }

    /// Sign with the opt-in V3 single-signature domain.
    ///
    /// Does not change [`Self::sign`]. Consumers must select V3 explicitly;
    /// signatures retain their byte format and do not carry a version tag.
    pub fn sign_v3(&self, msg: &[u8]) -> Signature {
        Signature((h0_single_v3(msg) * self.0).into())
    }

    /// Sign with the opt-in V3 multisignature domain.
    ///
    /// Uses the existing V2 key coefficients/aggregation but a separate
    /// message domain. Requires V3 verification; never activate implicitly
    /// for historical consensus messages.
    pub fn sign_multisig_v3(
        &self,
        pk: &PublicKey,
        msg: &[u8],
    ) -> MultisigSignature {
        MultisigSignature((h0_multisig_v3(msg) * (self.0 * h1(pk))).into())
    }

    /// Sign a message using the insecure v1 single-signature scheme.
    ///
    /// This path is considered insecure and is intentionally gated behind
    /// the `insecure-v1-signing` feature.
    #[cfg(feature = "insecure-v1-signing")]
    pub fn sign_insecure(&self, msg: &[u8]) -> Signature {
        // Hash message
        let h = h0_insecure_point(msg);

        // Multiply point by sk
        let e = h * self.0;
        Signature(e.into())
    }

    /// Sign a message using the default multi-signature behavior.
    pub fn sign_multisig(
        &self,
        pk: &PublicKey,
        msg: &[u8],
    ) -> MultisigSignature {
        let mut sig = self.sign(msg);

        // Turn signature into its modified construction,
        // which provides protection against rogue-key attacks.
        let t = h1(pk);
        sig.0 = (sig.0 * t).into();

        MultisigSignature(sig.0)
    }

    /// Sign a message using the insecure v1 multi-signature scheme.
    ///
    /// This path is considered insecure and is intentionally gated behind
    /// the `insecure-v1-signing` feature.
    #[cfg(feature = "insecure-v1-signing")]
    pub fn sign_multisig_insecure(
        &self,
        pk: &PublicKey,
        msg: &[u8],
    ) -> MultisigSignature {
        let mut sig = self.sign_insecure(msg);

        // Turn signature into its modified construction,
        // which provides protection against rogue-key attacks.
        let t = h1_insecure(pk);
        sig.0 = (sig.0 * t).into();

        MultisigSignature(sig.0)
    }
}
