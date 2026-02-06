// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "serde")]

use bls12_381_bls::{
    MultisigPublicKey, MultisigSignature, PublicKey, SecretKey, Signature,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Serialize;

fn assert_canonical_json<T>(
    input: &T,
    expected: &str,
) -> Result<String, Box<dyn std::error::Error>>
where
    T: ?Sized + Serialize,
{
    let serialized = serde_json::to_string(input)?;
    let input_canonical: serde_json::Value = serialized.parse()?;
    let expected_canonical: serde_json::Value = expected.parse()?;
    assert_eq!(input_canonical, expected_canonical);
    Ok(serialized)
}

#[test]
fn serde_public_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let pk = PublicKey::from(&SecretKey::random(&mut rng));
    let ser = assert_canonical_json(
        &pk,
        "\"shUGhHy4u1NiQY8uzHpTDagQJEqYrDJuAfgjDUVK5uBxbNi2D4aeHmCVaLvebvR4SGv5tJqGsg1KLRmeJu9RH2ANVELqvDU4Tr2zVBkTot47d1Gpj7N7UUMB1QF4aY3Vd96\"",
    )?;
    let deser: PublicKey = serde_json::from_str(&ser)?;
    assert_eq!(pk, deser);
    Ok(())
}

#[test]
fn serde_multisig_public_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let pk = MultisigPublicKey::aggregate(&[PublicKey::from(
        &SecretKey::random(&mut rng),
    )])
    .unwrap();
    let ser = assert_canonical_json(
        &pk,
        "\"25kghHWDNorWmBuDUTfXvKseTHzDvDnAN6jSsP44ptZ7C1apiarwVqwJ4quxx3Yax5TicNXTZsauZVwjHbzFyvxZAjGMEGcPAhrvzji5mxaiF445mTep3g9BJFeTbtv9sDR3\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(pk, deser);
    Ok(())
}

#[test]
fn serde_signature() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(&mut rng);
    let signature = sk.sign(b"a message");
    let ser = assert_canonical_json(
        &signature,
        "\"6UxktyK2QmZA6PsB15iTAiwYns3QLBrZmsBJPR1smfp4MNU3CnoqKLRbiUS1h76HW9\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(signature, deser);
    Ok(())
}

#[test]
fn serde_multisig_signature() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let signature = sk.sign_multisig(&pk, b"a message");
    let ser = assert_canonical_json(
        &signature,
        "\"79PPAVxpdTbHhK81p5oTGkEqb6EVkAkxEb39emBdzffLHwyTnfSbN6AmAiv3SdZMci\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(signature, deser);
    Ok(())
}

#[test]
fn serde_secret_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let sk = SecretKey::random(&mut rng);
    let ser = assert_canonical_json(
        &sk,
        "\"J96A6LyxZL3JdymeEHL4bNhf5MmcmgSLkd6Umh5ELrPt\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(sk, deser);
    Ok(())
}

#[test]
fn serde_wrong_encoded() {
    let wrong_encoded = "\"wrong-encoded\"";
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
fn serde_too_long_encoded() {
    let length_33_enc = "\"yaujE5CNg7SRYuf3Vw7G8QQdM7267QxJtfqGUEjLbxyCC\"";
    let length_49_enc = "\"RCR6kPYZDuew8ovT9MoxVv7mKRsbygumf2UTjvzs6AJhnukLj3BiFvjaE45Q41tKqdA\"";
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
fn serde_too_short_encoded() {
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
