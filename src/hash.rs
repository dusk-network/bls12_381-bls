// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Defines the hash functions needed for the BLS signature scheme.

use crate::PublicKey;

use dusk_bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use dusk_bls12_381::{BlsScalar, G1Affine, G1Projective};
use dusk_bytes::Serializable;
use sha2::Sha256;

const H0_V2_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_DUSK_V2";
const H1_V2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_DUSK_H1_V2";

#[inline]
fn h0_v1(msg: &[u8]) -> G1Affine {
    // Legacy (v1) map used by historical blocks/transactions.
    (G1Affine::generator() * BlsScalar::hash_to_scalar(msg)).into()
}

#[inline]
fn h0_v2(msg: &[u8]) -> G1Affine {
    // RFC9380-style hash-to-curve (random oracle) with explicit DST.
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        msg, H0_V2_DST,
    )
    .into()
}

/// h0 is the hash-to-curve-point function.
/// Hₒ : M -> Gₒ
pub fn h0(msg: &[u8]) -> G1Affine {
    h0_v1(msg)
}

/// h0 v2 hash-to-curve-point function.
pub fn h0_v2_point(msg: &[u8]) -> G1Affine {
    h0_v2(msg)
}

/// h1 is the hashing function used in the modified BLS
/// multi-signature construction.
/// H₁ : G₂ -> R
pub fn h1(pk: &PublicKey) -> BlsScalar {
    h1_v1(pk)
}

/// h1 v1 (legacy) function used for multisig coefficients.
pub fn h1_v1(pk: &PublicKey) -> BlsScalar {
    BlsScalar::hash_to_scalar(&pk.to_bytes())
}

/// h1 v2 function used for multisig coefficients.
pub fn h1_v2(pk: &PublicKey) -> BlsScalar {
    let mut material =
        [0u8; H1_V2_DST.len() + <PublicKey as Serializable<96>>::SIZE];
    material[..H1_V2_DST.len()].copy_from_slice(H1_V2_DST);
    material[H1_V2_DST.len()..].copy_from_slice(&pk.to_bytes());
    BlsScalar::hash_to_scalar(&material)
}
