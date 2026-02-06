// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bls12_381_bls::{MultisigPublicKey, PublicKey, SecretKey};
use criterion::{Criterion, criterion_group, criterion_main};
use dusk_bytes::Serializable;
use rand::RngCore;
use rand::rngs::OsRng;

fn random_message() -> [u8; 100] {
    let mut msg = [0u8; 100];
    (&mut OsRng::default()).fill_bytes(&mut msg);
    msg
}

fn bench_sign(c: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let msg = random_message();
    c.bench_function("sign", |b| b.iter(|| sk.sign(&msg)));
}

fn bench_multisig_sign(c: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);
    let msg = random_message();
    c.bench_function("multisig_sign", |b| {
        b.iter(|| sk.sign_multisig(&pk, &msg))
    });
}

fn bench_verify(c: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);
    let msg = random_message();
    let sig = sk.sign(&msg);
    c.bench_function("verify", |b| b.iter(|| pk.verify(&sig, &msg)));
}

fn bench_multisig_aggregate_sig(c: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);
    let msg = random_message();
    let sig = sk.sign_multisig(&pk, &msg);
    c.bench_function("multisig_aggregate_sig", |b| {
        b.iter(|| sig.aggregate(&[sig]))
    });
}

fn bench_multisig_aggregate_pk(c: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);
    c.bench_function("multisig_aggregate_pk", |b| {
        b.iter(|| MultisigPublicKey::aggregate(&[pk]))
    });
}

fn bench_multisig_aggregate_pk_64_bulk(c: &mut Criterion) {
    let mut pks = vec![];
    for _ in 0..64 {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);
        pks.push(pk)
    }
    c.bench_function("multisig_aggregate_pk_64_bulk", |b| {
        b.iter(|| MultisigPublicKey::aggregate(&pks[..]))
    });
}

fn bench_deser_compressed(c: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let bytes = PublicKey::from(&sk).to_bytes();
    c.bench_function("deser_compressed", |b| {
        b.iter(|| PublicKey::from_bytes(&bytes).unwrap())
    });
}

fn bench_deser_uncompressed(c: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let raw = PublicKey::from(&sk).to_raw_bytes();
    c.bench_function("deser_uncompressed", |b| {
        b.iter(|| unsafe { PublicKey::from_slice_unchecked(&raw) })
    });
}

criterion_group!(
    benches,
    bench_sign,
    bench_multisig_sign,
    bench_verify,
    bench_multisig_aggregate_sig,
    bench_multisig_aggregate_pk,
    bench_multisig_aggregate_pk_64_bulk,
    bench_deser_compressed,
    bench_deser_uncompressed,
);
criterion_main!(benches);
