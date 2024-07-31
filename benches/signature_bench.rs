// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![feature(test)]

extern crate test;

mod benches {
    use bls12_381_bls::{MultisigPublicKey, PublicKey, SecretKey};
    use dusk_bytes::Serializable;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use test::Bencher;

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let msg = random_message();
        b.iter(|| sk.sign(&msg));
    }

    #[bench]
    fn bench_multisig_sign(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);
        let msg = random_message();
        b.iter(|| sk.sign_multisig(&pk, &msg));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);
        let msg = random_message();
        let sig = sk.sign(&msg);
        b.iter(|| pk.verify(&sig, &msg));
    }

    #[bench]
    fn bench_multisig_aggregate_sig(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);
        let msg = random_message();
        let sig = sk.sign_multisig(&pk, &msg);
        b.iter(|| sig.aggregate(&[sig]));
    }

    #[bench]
    fn bench_multisig_aggregate_pk(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);
        b.iter(|| MultisigPublicKey::aggregate(&[pk]));
    }

    #[bench]
    fn bench_multisig_aggregate_pk_64_bulk(b: &mut Bencher) {
        let mut pks = vec![];
        for _ in 0..64 {
            let sk = SecretKey::random(&mut OsRng);
            let pk = PublicKey::from(&sk);
            pks.push(pk)
        }
        b.iter(|| MultisigPublicKey::aggregate(&pks[..]));
    }

    fn random_message() -> [u8; 100] {
        let mut msg = [0u8; 100];
        (&mut OsRng::default()).fill_bytes(&mut msg);
        msg
    }

    mod deser {
        use super::*;
        #[bench]
        fn bench_deser_compressed(b: &mut Bencher) {
            let sk = SecretKey::random(&mut OsRng);
            let bytes = PublicKey::from(&sk).to_bytes();
            b.iter(|| PublicKey::from_bytes(&bytes).unwrap());
        }

        #[bench]
        fn bench_deser_uncompressed(b: &mut Bencher) {
            let sk = SecretKey::random(&mut OsRng);
            let raw = PublicKey::from(&sk).to_raw_bytes();
            b.iter(|| unsafe { PublicKey::from_slice_unchecked(&raw) });
        }
    }
}
