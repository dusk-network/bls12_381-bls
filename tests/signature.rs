// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bls12_381_bls::{Error, MultisigPublicKey, PublicKey, SecretKey};
use dusk_bls12_381::BlsScalar;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use std::collections::{BTreeMap, BTreeSet};

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

#[test]
fn signature_ord() {
    let rng = &mut StdRng::seed_from_u64(0x1618);

    let sk1 = SecretKey::random(rng);
    let sk2 = SecretKey::random(rng);
    let sk3 = SecretKey::random(rng);
    let msg = random_message(rng);

    let sig1 = sk1.sign(&msg);
    let sig2 = sk2.sign(&msg);
    let sig3 = sk3.sign(&msg);

    // Test that Ord is consistent with PartialOrd
    assert_eq!(sig1.partial_cmp(&sig2), Some(sig1.cmp(&sig2)));

    // Test that ordering is reflexive, antisymmetric, and transitive
    assert_eq!(sig1.cmp(&sig1), core::cmp::Ordering::Equal); // Reflexive

    let ord12 = sig1.cmp(&sig2);
    let ord21 = sig2.cmp(&sig1);
    assert_eq!(ord12, ord21.reverse()); // Antisymmetric

    let ord23 = sig2.cmp(&sig3);
    let ord13 = sig1.cmp(&sig3);
    // Transitive: if sig1 <= sig2 and sig2 <= sig3, then sig1 <= sig3
    if ord12 != core::cmp::Ordering::Greater
        && ord23 != core::cmp::Ordering::Greater
    {
        assert_ne!(ord13, core::cmp::Ordering::Greater);
    }

    // Test using Signature in BTreeSet
    let mut set = BTreeSet::new();
    assert!(set.insert(sig1));
    assert!(set.insert(sig2));
    assert!(set.insert(sig3));
    assert!(!set.insert(sig1)); // Duplicate should not be inserted
    assert_eq!(set.len(), 3);

    // Test using Signature as BTreeMap key
    let mut map = BTreeMap::new();
    map.insert(sig1, "sig1");
    map.insert(sig2, "sig2");
    assert_eq!(map.get(&sig1), Some(&"sig1"));

    // Test sorting
    let mut sigs = vec![sig3, sig1, sig2];
    sigs.sort();
    assert!(sigs[0] <= sigs[1]);
    assert!(sigs[1] <= sigs[2]);
}

#[test]
fn multisig_signature_ord() {
    let rng = &mut StdRng::seed_from_u64(0x1618);

    let sk1 = SecretKey::random(rng);
    let pk1 = PublicKey::from(&sk1);
    let sk2 = SecretKey::random(rng);
    let pk2 = PublicKey::from(&sk2);
    let msg = random_message(rng);

    let sig1 = sk1.sign_multisig(&pk1, &msg);
    let sig2 = sk2.sign_multisig(&pk2, &msg);
    let sig3 = sig1.aggregate(&[sig2]);

    // Test that Ord is consistent with PartialOrd
    assert_eq!(sig1.partial_cmp(&sig2), Some(sig1.cmp(&sig2)));

    // Test that ordering is reflexive, antisymmetric, and transitive
    assert_eq!(sig1.cmp(&sig1), core::cmp::Ordering::Equal); // Reflexive

    let ord12 = sig1.cmp(&sig2);
    let ord21 = sig2.cmp(&sig1);
    assert_eq!(ord12, ord21.reverse()); // Antisymmetric

    let ord23 = sig2.cmp(&sig3);
    let ord13 = sig1.cmp(&sig3);
    // Transitive: if sig1 <= sig2 and sig2 <= sig3, then sig1 <= sig3
    if ord12 != core::cmp::Ordering::Greater
        && ord23 != core::cmp::Ordering::Greater
    {
        assert_ne!(ord13, core::cmp::Ordering::Greater);
    }

    // Test using MultisigSignature in BTreeSet
    let mut set = BTreeSet::new();
    assert!(set.insert(sig1));
    assert!(set.insert(sig2));
    assert!(set.insert(sig3));
    assert_eq!(set.len(), 3);

    // Test using MultisigSignature as BTreeMap key
    let mut map = BTreeMap::new();
    map.insert(sig1, 1);
    map.insert(sig2, 2);
    assert_eq!(map.get(&sig1), Some(&1));

    // Test sorting
    let mut sigs = vec![sig3, sig1, sig2];
    sigs.sort();
    assert!(sigs[0] <= sigs[1]);
    assert!(sigs[1] <= sigs[2]);
}
