// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "insecure-v1-signing")]
use bls12_381_bls::Signature;
use bls12_381_bls::{MultisigPublicKey, PublicKey, SecretKey};
#[cfg(feature = "insecure-v1-signing")]
use dusk_bls12_381::BlsScalar;
#[cfg(feature = "insecure-v1-signing")]
use dusk_bls12_381::{G1Affine, G1Projective};
#[cfg(feature = "insecure-v1-signing")]
use dusk_bytes::Serializable;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

#[test]
fn secure_roundtrip_single_and_multisig_aggregate() {
    let rng = &mut StdRng::seed_from_u64(0x5151);
    let msg = random_message(rng);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let sig = sk.sign(&msg);
    assert!(pk.verify(&sig, &msg).is_ok());

    let mut pks = Vec::with_capacity(8);
    let mut sigs = Vec::with_capacity(8);
    for _ in 0..8 {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        sigs.push(sk.sign_multisig(&pk, &msg));
        pks.push(pk);
    }

    let agg_sig = sigs[1..]
        .iter()
        .copied()
        .fold(sigs[0], |acc, sig| acc.aggregate(&[sig]));
    let agg_pk = MultisigPublicKey::aggregate(&pks)
        .expect("current public-key aggregation should succeed");
    assert!(agg_pk.verify(&agg_sig, &msg).is_ok());
}

#[test]
fn secure_rejects_wrong_message_and_wrong_key() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);

    let msg = random_message(rng);
    let wrong_msg = random_message(rng);

    let sig = sk.sign(&msg);
    assert!(pk.verify(&sig, &wrong_msg).is_err());

    let other_pk = PublicKey::from(&SecretKey::random(rng));
    assert!(other_pk.verify(&sig, &msg).is_err());

    let ms_sig = sk.sign_multisig(&pk, &msg);
    let ms_pk = MultisigPublicKey::aggregate(&[pk])
        .expect("aggregation should succeed");
    assert!(ms_pk.verify(&ms_sig, &wrong_msg).is_err());

    let wrong_ms_pk = MultisigPublicKey::aggregate(&[other_pk])
        .expect("aggregation should succeed");
    assert!(wrong_ms_pk.verify(&ms_sig, &msg).is_err());
}

#[test]
fn secure_signatures_are_not_valid_under_insecure_rules() {
    let rng = &mut StdRng::seed_from_u64(0xdead);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign(&msg);
    assert!(pk.verify(&sig, &msg).is_ok());
    assert!(pk.verify_insecure(&sig, &msg).is_err());

    let ms_sig = sk.sign_multisig(&pk, &msg);
    let ms_pk_insecure = MultisigPublicKey::aggregate_insecure(&[pk])
        .expect("insecure aggregation should succeed");
    assert!(ms_pk_insecure.verify_insecure(&ms_sig, &msg).is_err());
}

#[test]
#[cfg(feature = "insecure-v1-signing")]
fn insecure_signatures_are_not_valid_under_secure_rules() {
    let rng = &mut StdRng::seed_from_u64(0xcafe);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign_insecure(&msg);
    assert!(pk.verify_insecure(&sig, &msg).is_ok());
    assert!(pk.verify(&sig, &msg).is_err());

    let ms_sig = sk.sign_multisig_insecure(&pk, &msg);
    let ms_pk_insecure = MultisigPublicKey::aggregate_insecure(&[pk])
        .expect("insecure aggregation should succeed");
    assert!(ms_pk_insecure.verify_insecure(&ms_sig, &msg).is_ok());

    let ms_pk_secure = MultisigPublicKey::aggregate(&[pk])
        .expect("aggregation should succeed");
    assert!(ms_pk_secure.verify(&ms_sig, &msg).is_err());
}

#[test]
#[cfg(feature = "insecure-v1-signing")]
fn insecure_linear_forgery_is_rejected_by_secure_verifier() {
    let rng = &mut StdRng::seed_from_u64(0x1337);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);

    let msg1 = random_message(rng);
    let msg2 = random_message(rng);
    let msg3 = random_message(rng);

    let sig1 = sk.sign_insecure(&msg1);
    let sig2 = sk.sign_insecure(&msg2);

    let h1 = BlsScalar::hash_to_scalar(&msg1);
    let h2 = nonzero_hash(&msg2);
    let h3 = BlsScalar::hash_to_scalar(&msg3);

    // Choose a = 1 and solve b such that h1 + b*h2 = h3 (mod r).
    let b = (h3 - h1) * h2.invert().expect("non-zero scalar must invert");

    let s1 = sig_to_projective(&sig1);
    let s2 = sig_to_projective(&sig2);
    let forged = s1 + s2 * b;
    let forged = signature_from_projective(forged);

    assert!(pk.verify_insecure(&forged, &msg3).is_ok());
    assert!(pk.verify(&forged, &msg3).is_err());
}

fn random_message(rng: &mut StdRng) -> [u8; 100] {
    let mut msg = [0u8; 100];
    rng.fill_bytes(&mut msg);
    msg
}

#[cfg(feature = "insecure-v1-signing")]
fn sig_to_projective(sig: &Signature) -> G1Projective {
    let bytes = sig.to_bytes();
    let affine = G1Affine::from_bytes(&bytes).expect("signature bytes valid");
    G1Projective::from(affine)
}

#[cfg(feature = "insecure-v1-signing")]
fn signature_from_projective(p: G1Projective) -> Signature {
    let affine: G1Affine = p.into();
    Signature::from_bytes(&affine.to_bytes())
        .expect("constructed projective should serialize to signature")
}

#[cfg(feature = "insecure-v1-signing")]
fn nonzero_hash(msg: &[u8]) -> BlsScalar {
    let mut h = BlsScalar::hash_to_scalar(msg);
    if h.is_zero().into() {
        h = BlsScalar::one();
    }
    h
}
