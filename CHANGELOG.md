# Changelog

All notable changes follow Keep a Changelog and semantic versioning.

## Unreleased

### Changed

- Adopt the checksum-verified `go-library-tools` v1.4.0 CLI, schema-v2
  cohesion contract, and repository-local cohesion and online specification
  gates without changing secret-envelope API or runtime behavior.
- Pin reusable CI to the immutable v1.4.0 W14-enforcement workflow while
  retaining the fail-closed required CI contract.

- Govern the externally attributable AES-GCM and AWS KMS contracts separately
  from the repository-owned envelope, context, keyring, and defensive policies
  in the [specification decision register](docs/specification-decisions.md).
- Replace copied repository tooling with the checksum-pinned
  `go-library-tools` v1.2.0 specification-governance contract while retaining
  package-owned policy and verification evidence.

### Documentation

- Complete installation, package-selection, ownership, lifecycle, concurrency,
  cancellation, error, troubleshooting, performance, platform, and operational
  guidance; add a compiler-checked keyring example; and link the canonical
  v1.5.3 ecosystem index.
- Correct the v1.0.0 date to 2026-08-26, matching the signed annotated tag and
  [published GitHub release](https://github.com/faustbrian/go-secret-envelope/releases/tag/v1.0.0).
- Remove the unsubstantiated `go-config` companion relationship and `New(Config)`
  construction classification from Cohesion metadata without changing
  dependencies or runtime behavior.
- Record the behavior-neutral reviews of AWS SDK for Go v2 KMS v1.55.0 through
  v1.59.0 and refresh the monitored release-feed digest without changing the
  selected KMS source bindings or adapter contract.
- Publish the module's family, capabilities, ownership, lifecycle, supported
  environments, package selection, and delivery status, and link the README to
  the immutable v1.4.0 ecosystem index and family guidance.

- Record the initial specification decisions and their immutable content pins:
  - SECRETENVELOPE-DEC-001 sha256:47e0973213358b254b7ca58296233b6779fcecdb761cf975c612d7492ae2b499
  - SECRETENVELOPE-DEC-002 sha256:79bc3d45a65daba75fca8d276dd6e7d237770f9e56b02eb583604771ea34963c
  - SECRETENVELOPE-DEC-003 sha256:5601f98b707eaa19046bcdd1b375d80029a37c331808042ef034d296e1e32808
  - SECRETENVELOPE-DEC-004 sha256:59c31c52421cc25ec5e0bca69676f1d23d0d03d6fdf2813b573781dd86878685
  - SECRETENVELOPE-DEC-005 sha256:c97e2dbb63e6a5db83263ac7c07d30c102462cf75391f161e3e315fcd52a6b61
  - SECRETENVELOPE-DEC-006 sha256:26f5820f770ce12afa485176f09508f052a3507281a38d5b5afcfad18710606f
  - SECRETENVELOPE-DEC-007 sha256:dfc96be96b5aefe65fa6a879ed37d9172e64e391b5cf43d98de84e988629a5af
  - SECRETENVELOPE-DEC-008 sha256:8a379228e294467ae9ca437cd631a5682f12e7522d9141243fcdfae10cd89fe6
  - SECRETENVELOPE-DEC-009 sha256:4cec1b0206c8d3496eed1377d7415db10d088e241f51c4d2552115d7f47c9289
  - SECRETENVELOPE-DEC-010 sha256:73d3bae189459cd356d2e73815a3bf8ab66712ed01eaba307eae9167eb0d20ce
- Replace archived monorepo links and completed execution artifacts with a
  standalone, human-oriented documentation structure.

## 1.0.0 - 2026-08-26

### Changed

- Exclude intentional nested modules from root local-proxy archives so local,
  bootstrap, CI, and public module checksums describe the same source
  boundary.

- Track the pinned documentation-tool lockfile so clean CI checkouts install
  the exact validated cspell dependency.

- Reconcile standalone dependency checksums against deterministic current
  module archives so CI, local verification, and release consumers resolve
  identical content.

- Harden standalone documentation validation with deterministic spelling and
  link checks, package-specific documentation gates, and repository-local
  contributor guidance.

### Documentation

- Link the package README to package-owned documentation.

### Added

- Authenticated AES-256-GCM envelope encryption with immutable encryption
  contexts and a versioned binary persistence representation.
- AWS KMS data-key generation and decryption through a least-privilege client
  contract.
- A provider-neutral versioned keyring adapter for wrapping data keys with
  application keys delivered by an external secret manager.
- Verify-only AWS KMS authentication for bounded externally signed raw
  statements with explicit RSASSA-PSS, ECDSA, or Ed25519 algorithms and
  secret-safe typed failures.
- Exact statement coverage, race, fuzz, API, security, vulnerability, and
  documentation gates.

### Changed

- Publish the module from its standalone `github.com/faustbrian/go-secret-envelope` identity while preserving its documented API and behavior.
- Increased the authenticated plaintext bound to 4 MiB for bounded encrypted
  evidence and object-storage payloads.
- Hardened exact context, envelope, wrapped-key, and AWS KMS signature request
  boundaries, including minimum and maximum valid envelope encodings.
- Documented rotation and custody requirements for externally delivered
  keyrings without introducing a cloud runtime dependency.
