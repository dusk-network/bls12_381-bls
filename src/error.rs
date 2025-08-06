// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Error as DuskBytesError;

use core::fmt;

/// Standard error for the interface
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// Dusk-bytes serialization error
    BytesError(DuskBytesError),
    /// Cryptographic invalidity
    InvalidSignature,
    /// Invalid Point
    InvalidPoint,
    /// Tried to aggregate an empty list of public keys
    NoKeysProvided,
}

impl From<DuskBytesError> for Error {
    fn from(bytes_err: DuskBytesError) -> Self {
        Self::BytesError(bytes_err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BytesError(err) => write!(f, "{:?}", err),
            Self::InvalidSignature => {
                write!(f, "Invalid Signature")
            }
            Self::InvalidPoint => {
                write!(f, "Invalid Point")
            }
            Self::NoKeysProvided => {
                write!(f, "No keys provided")
            }
        }
    }
}

impl dusk_bytes::BadLength for Error {
    fn bad_length(found: usize, expected: usize) -> Self {
        DuskBytesError::bad_length(found, expected).into()
    }
}

impl dusk_bytes::InvalidChar for Error {
    fn invalid_char(ch: char, index: usize) -> Self {
        DuskBytesError::invalid_char(ch, index).into()
    }
}
