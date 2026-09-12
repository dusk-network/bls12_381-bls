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
// Dedicated scalar-domain DST for secure multisig coefficients.
const H1_DST: &[u8] = b"BLS_SIG_BLS12381_SCALAR_SHA256_DUSK_H1_V2";

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

/// Local opt-in V3 prototype: distinct message domains for the two schemes.
/// These tags do not replace V2 and require protocol review before activation.
pub(crate) fn h0_single_v3(msg: &[u8]) -> G1Affine {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        msg,
        b"BLS_SIG_BLS12381G1_XMD:SHA-256_DUSK_SINGLE_V3",
    )
    .into()
}

pub(crate) fn h0_multisig_v3(msg: &[u8]) -> G1Affine {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        msg,
        b"BLS_SIG_BLS12381G1_XMD:SHA-256_DUSK_MULTISIG_V3",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MultisigPublicKey, MultisigSignature, SecretKey, Signature};

    #[test]
    fn explicit_v3_rejects_cross_scheme_conversion_and_preserves_v2() {
        let sk = SecretKey::from(BlsScalar::from(7u64));
        let pk = PublicKey::from(&sk);
        let apk = MultisigPublicKey::aggregate(&[pk]).unwrap();
        let msg = b"same-key same-message compatibility probe";
        let coefficient = h1(&pk);
        let inverse = coefficient.invert().unwrap();

        // Frozen legacy behavior is intentionally retained, not silently fixed.
        let old = sk.sign(msg);
        let converted = MultisigSignature((old.0 * coefficient).into());
        assert_eq!(converted, sk.sign_multisig(&pk, msg));
        apk.verify(&converted, msg).unwrap();
        let back = Signature((converted.0 * inverse).into());
        assert_eq!(back, old);
        pk.verify(&back, msg).unwrap();

        let single = sk.sign_v3(msg);
        let multi = sk.sign_multisig_v3(&pk, msg);
        pk.verify_v3(&single, msg).unwrap();
        apk.verify_v3(&multi, msg).unwrap();
        assert!(
            apk.verify_v3(
                &MultisigSignature((single.0 * coefficient).into()),
                msg
            )
            .is_err()
        );
        assert!(
            pk.verify_v3(&Signature((multi.0 * inverse).into()), msg)
                .is_err()
        );
        assert!(pk.verify_v3(&old, msg).is_err());
        assert!(apk.verify_v3(&converted, msg).is_err());
        assert!(pk.verify(&single, msg).is_err());
        assert!(apk.verify(&multi, msg).is_err());
        assert!(pk.verify_v3(&single, b"different").is_err());
        assert!(PublicKey::default().verify_v3(&single, msg).is_err());
        assert!(pk.verify_v3(&Signature::default(), msg).is_err());

        let other_sk = SecretKey::from(BlsScalar::from(11u64));
        let other_pk = PublicKey::from(&other_sk);
        let aggregate_key =
            MultisigPublicKey::aggregate(&[pk, other_pk]).unwrap();
        let aggregate =
            multi.aggregate(&[other_sk.sign_multisig_v3(&other_pk, msg)]);
        aggregate_key.verify_v3(&aggregate, msg).unwrap();
        assert!(aggregate_key.verify(&aggregate, msg).is_err());
    }
}
