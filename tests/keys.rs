// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.
use std::collections::{BTreeMap, BTreeSet};

use bls12_381_bls::{Error, MultisigPublicKey, PublicKey, SecretKey};
use dusk_bls12_381::{BlsScalar, G2Affine};
use dusk_bytes::Serializable;
use rand::rngs::StdRng;
use rand::SeedableRng;
use zeroize::Zeroize;

#[test]
fn sk_zeroize() {
    let secret = BlsScalar::from(42);
    let mut sk = SecretKey::from(secret);

    sk.zeroize();
    assert_eq!(sk, SecretKey::default());
}

#[test]
fn keys_encoding() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let mspk = MultisigPublicKey::aggregate(&[pk])
        .expect("Aggregating should succeed");

    assert_eq!(sk, SecretKey::from_bytes(&sk.to_bytes()).unwrap());
    assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
    assert_eq!(
        mspk,
        MultisigPublicKey::from_bytes(&mspk.to_bytes()).unwrap()
    );
}

#[test]
fn apk_identity_fails() {
    let mut rng = StdRng::seed_from_u64(0xba0bab);

    let sk1 = SecretKey::random(&mut rng);
    let pk1 = PublicKey::from(&sk1);
    let sk2 = SecretKey::random(&mut rng);
    let pk2 = PublicKey::from(&sk2);
    let identity = PublicKey::from(&SecretKey::from(BlsScalar::zero()));

    assert_eq!(
        MultisigPublicKey::aggregate(&[identity, pk1, pk2]).unwrap_err(),
        Error::InvalidPoint
    );
    assert_eq!(
        MultisigPublicKey::aggregate(&[pk1, identity, pk2]).unwrap_err(),
        Error::InvalidPoint
    );
    assert_eq!(
        MultisigPublicKey::aggregate(&[pk1, pk2, identity]).unwrap_err(),
        Error::InvalidPoint
    );
}

#[test]
fn public_key_ord() {
    let mut rng = StdRng::seed_from_u64(0xc0ffee);

    let sk1 = SecretKey::random(&mut rng);
    let pk1 = PublicKey::from(&sk1);
    let sk2 = SecretKey::random(&mut rng);
    let pk2 = PublicKey::from(&sk2);
    let sk3 = SecretKey::random(&mut rng);
    let pk3 = PublicKey::from(&sk3);

    // Test that Ord is consistent with PartialOrd
    assert_eq!(pk1.partial_cmp(&pk2), Some(pk1.cmp(&pk2)));
    assert_eq!(pk2.partial_cmp(&pk3), Some(pk2.cmp(&pk3)));
    assert_eq!(pk1.partial_cmp(&pk3), Some(pk1.cmp(&pk3)));

    // Test that ordering is reflexive, antisymmetric, and transitive
    assert_eq!(pk1.cmp(&pk1), core::cmp::Ordering::Equal); // Reflexive

    let ord12 = pk1.cmp(&pk2);
    let ord21 = pk2.cmp(&pk1);
    assert_eq!(ord12, ord21.reverse()); // Antisymmetric

    let ord23 = pk2.cmp(&pk3);
    let ord13 = pk1.cmp(&pk3);

    // Transitive: if pk1 <= pk2 and pk2 <= pk3, then pk1 <= pk3
    if ord12 != core::cmp::Ordering::Greater
        && ord23 != core::cmp::Ordering::Greater
    {
        assert_ne!(ord13, core::cmp::Ordering::Greater);
    }

    // Test using PublicKey in BTreeSet
    let mut set = BTreeSet::new();
    assert!(set.insert(pk1));
    assert!(set.insert(pk2));
    assert!(set.insert(pk3));
    assert!(!set.insert(pk1)); // Duplicate should not be inserted
    assert_eq!(set.len(), 3);
    assert!(set.contains(&pk1));
    assert!(set.contains(&pk2));
    assert!(set.contains(&pk3));

    // Test using PublicKey as BTreeMap key
    let mut map = BTreeMap::new();
    map.insert(pk1, "first");
    map.insert(pk2, "second");
    map.insert(pk3, "third");
    assert_eq!(map.get(&pk1), Some(&"first"));
    assert_eq!(map.get(&pk2), Some(&"second"));
    assert_eq!(map.get(&pk3), Some(&"third"));

    // Test sorting
    let mut keys = vec![pk3, pk1, pk2];
    keys.sort();
    assert!(keys[0] <= keys[1]);
    assert!(keys[1] <= keys[2]);
}

#[test]
fn multisig_public_key_ord() {
    let mut rng = StdRng::seed_from_u64(0xdecaf);

    let sk1 = SecretKey::random(&mut rng);
    let pk1 = PublicKey::from(&sk1);
    let sk2 = SecretKey::random(&mut rng);
    let pk2 = PublicKey::from(&sk2);
    let sk3 = SecretKey::random(&mut rng);
    let pk3 = PublicKey::from(&sk3);

    let mspk1 = MultisigPublicKey::aggregate(&[pk1]).unwrap();
    let mspk2 = MultisigPublicKey::aggregate(&[pk2]).unwrap();
    let mspk3 = MultisigPublicKey::aggregate(&[pk1, pk2, pk3]).unwrap();

    // Test that Ord is consistent with PartialOrd
    assert_eq!(mspk1.partial_cmp(&mspk2), Some(mspk1.cmp(&mspk2)));

    // Test reflexivity
    assert_eq!(mspk1.cmp(&mspk1), core::cmp::Ordering::Equal);

    // Test using MultisigPublicKey in BTreeSet
    let mut set = BTreeSet::new();
    assert!(set.insert(mspk1));
    assert!(set.insert(mspk2));
    assert!(set.insert(mspk3));
    assert_eq!(set.len(), 3);

    // Test using MultisigPublicKey as BTreeMap key
    let mut map = BTreeMap::new();
    map.insert(mspk1, 1);
    map.insert(mspk2, 2);
    map.insert(mspk3, 3);
    assert_eq!(map.get(&mspk1), Some(&1));
}

#[test]
fn g2affine_padding_verification() {
    // Verify that G2Affine has padding bytes as expected.
    // G2Affine layout: { x: Fp2 (96 bytes), y: Fp2 (96 bytes), infinity: Choice
    // (1 byte) }
    // Expected: 193 bytes of actual data + 7 bytes padding = 200 bytes total

    // This test is in here so that it fails, if the layout of G2Affine ever
    // changes.

    const EXPECTED_MEANINGFUL_SIZE: usize = 193; // G2Affine::RAW_SIZE
    const EXPECTED_TOTAL_SIZE: usize = 200; // Rounded to 8-byte alignment

    // Verify the struct has padding
    assert_eq!(
        core::mem::size_of::<G2Affine>(),
        EXPECTED_TOTAL_SIZE,
        "G2Affine should be 200 bytes (193 data + 7 padding)"
    );

    // Verify RAW_SIZE is the meaningful data size
    assert_eq!(
        G2Affine::RAW_SIZE,
        EXPECTED_MEANINGFUL_SIZE,
        "G2Affine::RAW_SIZE should be 193 bytes (actual data)"
    );

    // Verify the padding exists
    let padding_bytes = core::mem::size_of::<G2Affine>() - G2Affine::RAW_SIZE;
    assert_eq!(
        padding_bytes, 7,
        "G2Affine should have exactly 7 padding bytes at the end"
    );
}
