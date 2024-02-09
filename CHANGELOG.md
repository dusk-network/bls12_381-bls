# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Change the implementation for hashing a slice of bytes into a BlsScalar to `BlsScalar::hash_to_scalar` [#3]
- Check validity of `PublicKey` and `Signature` points in signature verification [#7]

### Added

- Add `is_valid` check for `PublicKey` [#7]
- Add `Error::InvalidPoint` variant for invalid `PublicKey` and `Signature` points [#7]

## [0.1.0] - 2024-01-08

### Added

- Add initial commit, this package continues the development of [dusk-bls12_381-sign](https://github.com/dusk-network/bls12_381-sign/) at version `0.6.0` under the new name: `bls12_381-bls` and without the go related code.

<!-- ISSUES -->
[#7]: https://github.com/dusk-network/bls12_381-bls/issues/7
[#3]: https://github.com/dusk-network/bls12_381-bls/issues/3

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/bls12_381-bls/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dusk-network/bls12_381-bls/releases/tag/v0.1.0
