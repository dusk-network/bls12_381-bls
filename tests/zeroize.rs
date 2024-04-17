// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bls12_381_bls::SecretKey;
use dusk_bls12_381::BlsScalar;
use zeroize::Zeroize;

#[test]
fn secret_key() {
    let secret = BlsScalar::from(42);
    let mut sk = SecretKey::from(secret);

    sk.zeroize();
    assert_eq!(sk, SecretKey::default());
}
