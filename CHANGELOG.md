# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2019-12-29
### Fixed
- Root certificate loading when this gem is used as a dependency

### Changed
- Rename `Statement#certificates` to `Statement#certificate_chain`

## [0.3.0] - 2019-12-29
### Added
- `Statement#certificates` exposes the certificate chain used during verification
- `Statement#verify` takes an optional `time` argument, defaulting to the current time. This can be used for testing
  captured statements from real devices without needing stubbing.

## [0.2.0] - 2019-12-28
### Fixed
- Fixed loading bundled root certificates

## [0.1.0] - 2019-12-28
### Added
- Extracted from [webauthn-ruby](https://github.com/cedarcode/webauthn-ruby) after discussion with the maintainers. Thanks for the feedback @grzuy and @brauliomartinezlm!

[Unreleased]: https://github.com/bdewater/safety_net_attestation/compare/v0.1.0...HEAD
[0.4.0]: https://github.com/bdewater/safety_net_attestation/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/bdewater/safety_net_attestation/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bdewater/safety_net_attestation/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bdewater/safety_net_attestation/releases/tag/v0.1.0
