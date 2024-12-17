// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "serde")]

use bls12_381_bls::{
    MultisigPublicKey, MultisigSignature, PublicKey, SecretKey, Signature,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn public_key() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let pk = PublicKey::from(&SecretKey::random(&mut rng));
    let ser = serde_json::to_string(&pk);
    let deser = serde_json::from_str(&ser.unwrap());
    assert_eq!(pk, deser.unwrap());
}

#[test]
fn multisig_public_key() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let pk = MultisigPublicKey::aggregate(&[PublicKey::from(
        &SecretKey::random(&mut rng),
    )])
    .unwrap();
    let ser = serde_json::to_string(&pk);
    let deser = serde_json::from_str(&ser.unwrap());
    assert_eq!(pk, deser.unwrap());
}

#[test]
fn signature() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(&mut rng);
    let signature = sk.sign(b"a message");
    let ser = serde_json::to_string(&signature).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(signature, deser);
}

#[test]
fn multisig_signature() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let signature = sk.sign_multisig(&pk, b"a message");
    let ser = serde_json::to_string(&signature).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(signature, deser);
}

#[test]
fn secret_key() {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(&mut rng);
    let ser = serde_json::to_string(&sk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(sk, deser);
}

#[test]
fn wrong_encoded() {
    let wrong_encoded = "wrong-encoded";
    let public_key: Result<PublicKey, _> = serde_json::from_str(&wrong_encoded);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&wrong_encoded);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(&wrong_encoded);
    assert!(signature.is_err());

    let public_key_double: Result<MultisigPublicKey, _> =
        serde_json::from_str(&wrong_encoded);
    assert!(public_key_double.is_err());

    let signature_double: Result<MultisigSignature, _> =
        serde_json::from_str(&wrong_encoded);
    assert!(signature_double.is_err());
}

#[test]
fn too_long_encoded() {
    let length_33_enc = "\"yaujE5CNg7SRYuf3Vw7G8QQdM7267QxJtfqGUEjLbxyCC\"";
    let length_49_enc= "\"RCR6kPYZDuew8ovT9MoxVv7mKRsbygumf2UTjvzs6AJhnukLj3BiFvjaE45Q41tKqdA\"";
    let length_97_enc = "\"7a5RpCdtr1aaXvaR3AofnEnVRh7kpzyqE8eYJpCBVLKLLpXVeN9UrXGRTZyq2upTVaJT5QnPQwZCGXW1oxrEAzrPvQ4vbWFwiHMJijZMzrPsTjQJFju1H4shrajuqUG4fYFpC\"";

    let public_key: Result<PublicKey, _> = serde_json::from_str(&length_97_enc);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&length_33_enc);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(&length_49_enc);
    assert!(signature.is_err());

    let multisig_public_key: Result<MultisigPublicKey, _> =
        serde_json::from_str(&length_97_enc);
    assert!(multisig_public_key.is_err());

    let multisig_signature: Result<MultisigSignature, _> =
        serde_json::from_str(&length_49_enc);
    assert!(multisig_signature.is_err());
}

#[test]
fn too_short_encoded() {
    let length_31_enc = "\"3uTp29S3e2HQBekFYvVwsmoeEzk4uVWwQUjvJPwWKwU\"";
    let length_47_enc =
        "\"2F3DDEDEuxrszs3JfzFq51tnGNm3ZtrHwa7sAA4pkeo1JkqGTEYudnBZLNAkCohAd\"";
    let length_95_enc = "\"LZXkPWnz5xKxYnyDRZyJvL9vF44oQynzozqRBcpgWA3yZicbaxNeKKJrAMv3eXBbyEvk24mgz9Kg9tck5yEW6k16chN4hDWYUr5gDb9PJJ3YmUqcjG8yPaAuz3cNCE8dHv\"";

    let public_key: Result<PublicKey, _> = serde_json::from_str(&length_95_enc);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&length_31_enc);
    assert!(secret_key.is_err());

    let signature: Result<Signature, _> = serde_json::from_str(&length_47_enc);
    assert!(signature.is_err());

    let multisig_public_key: Result<MultisigPublicKey, _> =
        serde_json::from_str(&length_95_enc);
    assert!(multisig_public_key.is_err());

    let multisig_signature: Result<MultisigSignature, _> =
        serde_json::from_str(&length_47_enc);
    assert!(multisig_signature.is_err());
}
