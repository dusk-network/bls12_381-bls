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

const H0_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_DUSK_V2";
const H1_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_DUSK_H1_V2";

#[inline]
fn h0_insecure(msg: &[u8]) -> G1Affine {
    // Insecure v1 map used by historical blocks/transactions.
    (G1Affine::generator() * BlsScalar::hash_to_scalar(msg)).into()
}

/// Hash-to-curve-point function for the secure path.
pub fn h0(msg: &[u8]) -> G1Affine {
    // RFC9380-style hash-to-curve (random oracle) with explicit DST.
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        msg, H0_DST,
    )
    .into()
}

/// Insecure v1 hash-to-curve-point function.
pub fn h0_insecure_point(msg: &[u8]) -> G1Affine {
    h0_insecure(msg)
}

/// Insecure v1 function used for multisig coefficients.
pub fn h1_insecure(pk: &PublicKey) -> BlsScalar {
    BlsScalar::hash_to_scalar(&pk.to_bytes())
}

/// Scalar function used for multisig coefficients on the secure path.
pub fn h1(pk: &PublicKey) -> BlsScalar {
    let mut material =
        [0u8; H1_DST.len() + <PublicKey as Serializable<96>>::SIZE];
    material[..H1_DST.len()].copy_from_slice(H1_DST);
    material[H1_DST.len()..].copy_from_slice(&pk.to_bytes());
    BlsScalar::hash_to_scalar(&material)
}
