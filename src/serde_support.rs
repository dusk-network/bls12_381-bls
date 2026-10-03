// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use alloc::format;
use core::fmt;

use dusk_bytes::Serializable;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    MultisigPublicKey, MultisigSignature, PublicKey, SecretKey, Signature,
};

/// Decodes a Base58 string of exactly `N` bytes into `T`.
///
/// Longer encodings are rejected before decoding, and decoding writes into a
/// fixed-size stack buffer.
fn deserialize_bs58<'de, D, T, const N: usize>(
    deserializer: D,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Serializable<N>,
    T::Error: fmt::Debug,
{
    struct Bs58<const N: usize>;

    impl<const N: usize> Visitor<'_> for Bs58<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a base58 string encoding {N} bytes")
        }

        fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
            self.visit_bytes(value.as_bytes())
        }

        fn visit_bytes<E: Error>(self, value: &[u8]) -> Result<Self::Value, E> {
            // `N` bytes encode to at most `ceil(N * log(256) / log(58))`
            // characters, and log(256) / log(58) < 1.366.
            if value.len() > N * 1366 / 1000 + 1 {
                return Err(E::invalid_length(value.len(), &self));
            }
            let mut bytes = [0; N];
            let len =
                bs58::decode(value).onto(&mut bytes).map_err(E::custom)?;
            if len != N {
                return Err(E::invalid_length(len, &self));
            }
            Ok(bytes)
        }
    }

    let bytes = deserializer.deserialize_str(Bs58::<N>)?;
    T::from_bytes(&bytes).map_err(|err| D::Error::custom(format!("{err:?}")))
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}

impl Serialize for MultisigPublicKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for MultisigPublicKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}

impl Serialize for MultisigSignature {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for MultisigSignature {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}
