// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bls12_381_bls::{Error, MultisigPublicKey, PublicKey, SecretKey};
use dusk_bls12_381::BlsScalar;
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

fn random_message(rng: &mut StdRng) -> [u8; 100] {
    let mut msg = [0u8; 100];

    rng.fill_bytes(&mut msg);

    msg
}
