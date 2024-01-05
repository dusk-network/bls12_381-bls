// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Defines the hash functions needed for the BLS signature scheme.

use crate::PublicKey;

use blake2::digest::consts::U32;
use blake2::Digest;
use dusk_bls12_381::{BlsScalar, G1Affine};
use dusk_bytes::Serializable;

type Blake2b = blake2::Blake2b<U32>;

/// Hash an arbitrary slice of bytes into a [`BlsScalar`]
fn h(msg: &[u8]) -> BlsScalar {
    let mut digest: [u8; BlsScalar::SIZE] = Blake2b::digest(msg).into();

    // Truncate the contract id to fit bls
    digest[31] &= 0x3f;

    let hash: Option<BlsScalar> = BlsScalar::from_bytes(&digest).into();
    hash.unwrap_or_default()
}

/// h0 is the hash-to-curve-point function.
/// Hₒ : M -> Gₒ
pub fn h0(msg: &[u8]) -> G1Affine {
    // Now multiply this message by the G1 base point,
    // to generate a G1Affine.
    (G1Affine::generator() * h(msg)).into()
}

/// h1 is the hashing function used in the modified BLS
/// multi-signature construction.
/// H₁ : G₂ -> R
pub fn h1(pk: &PublicKey) -> BlsScalar {
    h(&pk.to_bytes())
}
