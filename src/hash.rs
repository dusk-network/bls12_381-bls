// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Defines the hash functions needed for the BLS signature scheme.

use crate::PublicKey;

use dusk_bls12_381::{BlsScalar, G1Affine};
use dusk_bytes::Serializable;

/// h0 is the hash-to-curve-point function.
/// Hₒ : M -> Gₒ
pub fn h0(msg: &[u8]) -> G1Affine {
    // Now multiply this message by the G1 base point,
    // to generate a G1Affine.
    (G1Affine::generator() * BlsScalar::hash_to_scalar(msg)).into()
}

/// h1 is the hashing function used in the modified BLS
/// multi-signature construction.
/// H₁ : G₂ -> R
pub fn h1(pk: &PublicKey) -> BlsScalar {
    BlsScalar::hash_to_scalar(&pk.to_bytes())
}
