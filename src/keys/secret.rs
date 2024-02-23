// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::hash::{h0, h1};
use crate::{PublicKey, Signature};

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error as DuskBytesError, Serializable};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// A BLS secret key, holding a BLS12-381 scalar inside.
/// Can be used for signing messages.
#[derive(Default, Clone, Debug, Eq, PartialEq)]
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
    /// Sign a message, producing a [`Signature`].
    /// The signature produced is vulnerable to a rogue-key attack.
    pub fn sign_vulnerable(&self, msg: &[u8]) -> Signature {
        // Hash message
        let h = h0(msg);

        // Multiply point by sk
        let e = h * self.0;
        Signature(e.into())
    }

    /// Sign a message in a rogue-key attack resistant way.
    pub fn sign(&self, pk: &PublicKey, msg: &[u8]) -> Signature {
        let mut sig = self.sign_vulnerable(msg);

        // Turn signature into its modified construction,
        // which provides protection against rogue-key attacks.
        let t = h1(pk);
        sig.0 = (sig.0 * t).into();
        sig
    }

    /// Erase the content of the [`SecretKey`] from memory to prevent leaking
    /// sensitive data after the [`SecretKey`] goes out of scope.
    pub fn zeroize(&mut self) {
        self.0 .0.zeroize();
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize() {
        let sk = SecretKey::from(BlsScalar::from(42));
        let ptr = sk.as_ref().0.as_ptr();
        drop(sk);

        // we would expect that the memory is erased during `drop` but it is
        // still there
        unsafe {
            assert_eq!(
                core::slice::from_raw_parts(ptr, 4),
                BlsScalar::from(42).0
            );
        };

        // let's try again and call zeroize explicitly:
        let mut sk = SecretKey::from(BlsScalar::from(42));
        let ptr = sk.as_ref().0.as_ptr();
        sk.zeroize();
        drop(sk);

        // now the check passes
        unsafe {
            assert_eq!(core::slice::from_raw_parts(ptr, 4), [0; 4]);
        };
    }
}
