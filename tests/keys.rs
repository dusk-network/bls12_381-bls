// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bls12_381_bls::{Error, PublicKey, SecretKey, APK};
use dusk_bls12_381::BlsScalar;
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
    let apk = APK::from(&pk);

    assert_eq!(sk, SecretKey::from_bytes(&sk.to_bytes()).unwrap());
    assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
    assert_eq!(apk, APK::from_bytes(&apk.to_bytes()).unwrap());
}

#[test]
fn apk_identity_fails() {
    let mut rng = StdRng::seed_from_u64(0xba0bab);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let sk2 = SecretKey::random(&mut rng);
    let pk2 = PublicKey::from(&sk2);
    let sk3 = SecretKey::random(&mut rng);
    let pk3 = PublicKey::from(&sk3);
    let identity = PublicKey::from(&SecretKey::from(BlsScalar::zero()));

    let mut apk = APK::from(&pk);
    assert_eq!(
        apk.aggregate(&[identity, pk2, pk3]).unwrap_err(),
        Error::InvalidPoint
    );
    assert_eq!(
        apk.aggregate(&[pk2, identity, pk3]).unwrap_err(),
        Error::InvalidPoint
    );
    assert_eq!(
        apk.aggregate(&[pk2, pk3, identity]).unwrap_err(),
        Error::InvalidPoint
    );

    let mut apk = APK::from(&identity);
    assert_eq!(
        apk.aggregate(&[pk, pk2, pk3]).unwrap_err(),
        Error::InvalidPoint
    );
}
