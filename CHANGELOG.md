# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add serde `Serialize` and `Deserialize` implementations for `PublicKey`, `MultisigPublicKey`, `Signature`,
`MultisigSignature` and `SecretKey` [#21]
- Add `serde`, `bs58` and `serde_json` optional dependencies [#21]
- Add `serde` feature [#21]

## [0.4.0] - 2024-08-01

### Added

- Add `MultisigSignature` struct [#18]
- Add `Error::NoKeysProvided` variant [#18]

### Changed

- Rename `SecretKey::sign` to `sign_multisig` and change return to `MultisigSignature` [#18]
- Rename `SecretKey::sign_vulnerable` to `sign` [#18]
- Rename `APK` to `MultisigPublicKey` [#18]
- Change `APK::verify` to take a `MultisigSignature` [#18]

### Removed

- Remove `impl From<&PublicKey> for APK` [#18]
- Remove `impl From<&SecretKey> for APK` [#18]

## [0.3.1] - 2024-06-27

### Changed

- Early return from `APK::aggregate` on invalid keys

### Fixed

- Fix compilation of with the `parallel` feature

## [0.3.0] - 2024-04-24

### Changed

- Check validity of `PublicKey` and `Signature` points in signature verification [#7]
- Check validity of `PublicKey` points when aggregating them [#8]

### Added

- Add `is_valid` check for `PublicKey` [#7]
- Add `Error::InvalidPoint` variant for invalid `PublicKey` and `Signature` points [#7]
- Add `Zeroize` trait for `SecretKey` [#5]

### Removed

- Remove `Copy` trait for `SecretKey` [#5]
- Remove separate checks for point validity in `PublicKey` and `Signature` in favor of a singular `is_valid`

## [0.2.0] - 2024-02-28

### Changed

- Change the implementation for hashing a slice of bytes into a BlsScalar to `BlsScalar::hash_to_scalar` [#3]

## [0.1.0] - 2024-01-08

### Added

- Add initial commit, this package continues the development of [dusk-bls12_381-sign](https://github.com/dusk-network/bls12_381-sign/) at version `0.6.0` under the new name: `bls12_381-bls` and without the go related code.

<!-- ISSUES -->
[#21]: https://github.com/dusk-network/bls12_381-bls/issues/21
[#18]: https://github.com/dusk-network/bls12_381-bls/issues/18
[#8]: https://github.com/dusk-network/bls12_381-bls/issues/8
[#7]: https://github.com/dusk-network/bls12_381-bls/issues/7
[#5]: https://github.com/dusk-network/bls12_381-bls/issues/5
[#3]: https://github.com/dusk-network/bls12_381-bls/issues/3

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/bls12_381-bls/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/dusk-network/bls12_381-bls/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/dusk-network/bls12_381-bls/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/dusk-network/bls12_381-bls/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dusk-network/bls12_381-bls/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/bls12_381-bls/releases/tag/v0.1.0
