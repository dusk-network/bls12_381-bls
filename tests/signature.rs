// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bls12_381_bls::{
    Error, MultisigPublicKey, PublicKey, SecretKey, Signature,
};
use dusk_bls12_381::{BlsScalar, G1Affine, G1Projective};
use dusk_bytes::Serializable;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

#[test]
fn sign_verify() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let msg = random_message(rng);

    // Sign and verify.
    let sig = sk.sign(&msg);
    let pk = PublicKey::from(&sk);
    assert!(pk.verify(&sig, &msg).is_ok());
}

#[test]
fn sign_verify_incorrect_message() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let msg = random_message(rng);

    let sig = sk.sign(&msg);

    // Verify with a different message.
    let msg = random_message(rng);
    let pk = PublicKey::from(&sk);

    assert!(pk.verify(&sig, &msg).is_err());
}

#[test]
fn sign_verify_incorrect_pk() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let msg = random_message(rng);

    let sig = sk.sign(&msg);

    // Verify with a different public key.
    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    assert!(pk.verify(&sig, &msg).is_err());
}

#[test]
fn multisig_sign_verify() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign_multisig(&pk, &msg);

    let ms_pk = MultisigPublicKey::aggregate(&[pk])
        .expect("Aggregation should succeed");
    assert!(ms_pk.verify(&sig, &msg).is_ok());
}

#[test]
fn multisig_sign_verify_incorrect_message() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign_multisig(&pk, &msg);

    // Verification with a different message should fail.
    let ms_pk = MultisigPublicKey::aggregate(&[pk])
        .expect("Aggregation should succeed");
    let msg = random_message(rng);
    assert!(ms_pk.verify(&sig, &msg).is_err());
}

#[test]
fn multisig_sign_verify_incorrect_apk() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign_multisig(&pk, &msg);

    // Verification with another APK should fail.
    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let ms_pk = MultisigPublicKey::aggregate(&[pk])
        .expect("Aggregation should succeed");
    assert!(ms_pk.verify(&sig, &msg).is_err());
}

#[test]
fn multisig_sign_verify_aggregated() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let mut ms_sig = sk.sign_multisig(&pk, &msg);

    let mut pks = vec![pk];
    for _ in 0..10 {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        let sig = sk.sign_multisig(&pk, &msg);
        ms_sig = ms_sig.aggregate(&[sig]);
        pks.push(pk);
    }
    let ms_pk =
        MultisigPublicKey::aggregate(&pks).expect("Aggregation should succeed");

    assert!(ms_pk.verify(&ms_sig, &msg).is_ok());
}

#[test]
fn multisig_sign_verify_aggregated_incorrect_message() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let mut ms_sig = sk.sign_multisig(&pk, &msg);

    let mut pks = vec![pk];
    for _ in 0..10 {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        let sig = sk.sign_multisig(&pk, &msg);
        ms_sig = ms_sig.aggregate(&[sig]);
        pks.push(pk);
    }
    let ms_pk =
        MultisigPublicKey::aggregate(&pks).expect("Aggregation should succeed");

    // Verification should fail with a different message.
    let msg = random_message(rng);
    assert!(ms_pk.verify(&ms_sig, &msg).is_err());
}

#[test]
fn multisig_sign_verify_aggregated_incorrect_apk() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let mut ms_sig = sk.sign_multisig(&pk, &msg);

    for _ in 0..10 {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        let sig = sk.sign_multisig(&pk, &msg);
        ms_sig = ms_sig.aggregate(&[sig]);
    }

    // Verification with the wrong APK should fail.
    let ms_pk = MultisigPublicKey::aggregate(&[pk])
        .expect("Aggregation should succeed");
    assert!(ms_pk.verify(&ms_sig, &msg).is_err());
}

#[test]
fn multisig_sign_verify_identity_fails() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);
    let msg = random_message(rng);
    let sk = SecretKey::from(BlsScalar::zero());
    let pk = PublicKey::from(&sk);
    let sig = sk.sign(&msg);

    assert_eq!(pk.verify(&sig, &msg).unwrap_err(), Error::InvalidPoint);
}

#[test]
fn v1_signature_rejected_by_v2_verifier() {
    let rng = &mut StdRng::seed_from_u64(0xcafe);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign_v1(&msg);
    assert!(pk.verify_v1(&sig, &msg).is_ok());
    assert!(pk.verify_v2(&sig, &msg).is_err());
}

#[test]
fn v2_signature_rejected_by_v1_verifier() {
    let rng = &mut StdRng::seed_from_u64(0xdead);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign_v2(&msg);
    assert!(pk.verify_v2(&sig, &msg).is_ok());
    assert!(pk.verify_v1(&sig, &msg).is_err());
}

#[test]
fn multisig_v2_aggregate_and_verify() {
    let rng = &mut StdRng::seed_from_u64(0x5151);
    let msg = random_message(rng);

    let mut pks = Vec::with_capacity(8);
    let mut sigs = Vec::with_capacity(8);
    for _ in 0..8 {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        sigs.push(sk.sign_multisig_v2(&pk, &msg));
        pks.push(pk);
    }

    let agg_sig = sigs[1..]
        .iter()
        .copied()
        .fold(sigs[0], |acc, sig| acc.aggregate(&[sig]));
    let agg_pk = MultisigPublicKey::aggregate_v2(&pks)
        .expect("v2 public-key aggregation should succeed");

    assert!(agg_pk.verify_v2(&agg_sig, &msg).is_ok());
}

#[test]
fn v1_linear_forgery_fails_under_v2() {
    let rng = &mut StdRng::seed_from_u64(0x1337);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);

    let msg1 = random_message(rng);
    let msg2 = random_message(rng);
    let msg3 = random_message(rng);

    let sig1 = sk.sign_v1(&msg1);
    let sig2 = sk.sign_v1(&msg2);

    let h1 = BlsScalar::hash_to_scalar(&msg1);
    let h2 = nonzero_hash(&msg2);
    let h3 = BlsScalar::hash_to_scalar(&msg3);

    // Choose a = 1 and solve b such that h1 + b*h2 = h3 (mod r).
    let b = (h3 - h1) * h2.invert().expect("non-zero scalar must invert");

    let s1 = sig_to_projective(&sig1);
    let s2 = sig_to_projective(&sig2);
    let forged = s1 + s2 * b;
    let forged = signature_from_projective(forged);

    assert!(pk.verify_v1(&forged, &msg3).is_ok());
    assert!(pk.verify_v2(&forged, &msg3).is_err());
}

fn random_message(rng: &mut StdRng) -> [u8; 100] {
    let mut msg = [0u8; 100];

    rng.fill_bytes(&mut msg);

    msg
}

fn sig_to_projective(sig: &Signature) -> G1Projective {
    let bytes = sig.to_bytes();
    let affine = G1Affine::from_bytes(&bytes).expect("signature bytes valid");
    G1Projective::from(affine)
}

fn signature_from_projective(p: G1Projective) -> Signature {
    let affine: G1Affine = p.into();
    Signature::from_bytes(&affine.to_bytes())
        .expect("constructed projective should serialize to signature")
}

fn nonzero_hash(msg: &[u8]) -> BlsScalar {
    let mut h = BlsScalar::hash_to_scalar(msg);
    if h.is_zero().into() {
        h = BlsScalar::one();
    }
    h
}
