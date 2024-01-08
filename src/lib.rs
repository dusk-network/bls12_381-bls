// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![no_std]

//! Implementation of BLS signatures on the BLS12-381 curve.
//! Reference paper: https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html

mod error;
mod hash;
mod keys;
mod signature;

pub use error::Error;
pub use keys::{apk::APK, public::PublicKey, secret::SecretKey};
pub use signature::Signature;

#[cfg(feature = "rkyv-impl")]
pub use crate::keys::{
    apk::{APKResolver, ArchivedAPK},
    public::{ArchivedPublicKey, PublicKeyResolver},
    secret::{ArchivedSecretKey, SecretKeyResolver},
};

#[cfg(feature = "rkyv-impl")]
pub use crate::signature::{ArchivedSignature, SignatureResolver};
