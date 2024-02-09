// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bls12_381_bls::{Error, PublicKey, SecretKey, APK};
use dusk_bls12_381::BlsScalar;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

#[test]
fn vulnerable_sign_verify() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let msg = random_message(rng);

    // Sign and verify.
    let sig = sk.sign_vulnerable(&msg);
    let pk = PublicKey::from(&sk);
    assert!(pk.verify(&sig, &msg).is_ok());
}

#[test]
fn vulnerable_sign_verify_incorrect_message() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let msg = random_message(rng);

    let sig = sk.sign_vulnerable(&msg);

    // Verify with a different message.
    let msg = random_message(rng);
    let pk = PublicKey::from(&sk);

    assert!(pk.verify(&sig, &msg).is_err());
}

#[test]
fn vulnerable_sign_verify_incorrect_pk() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let msg = random_message(rng);

    let sig = sk.sign_vulnerable(&msg);

    // Verify with a different public key.
    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    assert!(pk.verify(&sig, &msg).is_err());
}

#[test]
fn sign_verify() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign(&pk, &msg);

    // Verification with the standard pk should fail.
    assert!(pk.verify(&sig, &msg).is_err());

    // Verification with the aggregated version should work.
    let apk = APK::from(&pk);
    assert!(apk.verify(&sig, &msg).is_ok());
}

#[test]
fn sign_verify_incorrect_message() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign(&pk, &msg);

    // Verification with a different message should fail.
    let apk = APK::from(&pk);
    let msg = random_message(rng);
    assert!(apk.verify(&sig, &msg).is_err());
}

#[test]
fn sign_verify_incorrect_apk() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let sig = sk.sign(&pk, &msg);

    // Verification with another APK should fail.
    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let apk = APK::from(&pk);
    assert!(apk.verify(&sig, &msg).is_err());
}

#[test]
fn sign_verify_aggregated() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let mut agg_sig = sk.sign(&pk, &msg);

    let mut apk = APK::from(&pk);

    let mut pks = vec![];
    for _ in 0..10 {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        let sig = sk.sign(&pk, &msg);
        agg_sig = agg_sig.aggregate(&[sig]);
        pks.push(pk)
    }
    apk.aggregate(&pks[..]);

    assert!(apk.verify(&agg_sig, &msg).is_ok());
}

#[test]
fn sign_verify_aggregated_incorrect_message() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let mut agg_sig = sk.sign(&pk, &msg);

    let mut apk = APK::from(&pk);

    for _ in 0..10 {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        let sig = sk.sign(&pk, &msg);
        agg_sig = agg_sig.aggregate(&[sig]);
        apk.aggregate(&[pk]);
    }

    // Verification should fail with a different message.
    let msg = random_message(rng);
    assert!(apk.verify(&agg_sig, &msg).is_err());
}

#[test]
fn sign_verify_aggregated_incorrect_apk() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let sk = SecretKey::random(rng);
    let pk = PublicKey::from(&sk);
    let msg = random_message(rng);

    let mut agg_sig = sk.sign(&pk, &msg);

    let mut apk = APK::from(&pk);

    for _ in 0..10 {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        let sig = sk.sign(&pk, &msg);
        agg_sig = agg_sig.aggregate(&[sig]);
        apk.aggregate(&[pk]);
    }

    // Verification with the wrong APK should fail.
    let apk = APK::from(&pk);
    assert!(apk.verify(&agg_sig, &msg).is_err());
}

#[test]
fn sign_verify_identity_fails() {
    let rng = &mut StdRng::seed_from_u64(0xbeef);
    let msg = random_message(rng);
    let sk = SecretKey::from(BlsScalar::zero());
    let pk = PublicKey::from(&sk);
    let sig = sk.sign_vulnerable(&msg);

    assert_eq!(pk.verify(&sig, &msg).unwrap_err(), Error::InvalidPoint);
}

fn random_message(rng: &mut StdRng) -> [u8; 100] {
    let mut msg = [0u8; 100];

    rng.fill_bytes(&mut msg);

    msg
}
