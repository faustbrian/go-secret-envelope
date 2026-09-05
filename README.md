# secret-envelope

[![CI](https://github.com/faustbrian/go-secret-envelope/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/faustbrian/go-secret-envelope/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/badge/CodeQL-required-blue)](https://github.com/faustbrian/go-secret-envelope/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Mutation](https://img.shields.io/badge/mutation-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Documentation](https://img.shields.io/badge/docs-checked_in_CI-blue)](docs/)
[![Go Reference](https://pkg.go.dev/badge/github.com/faustbrian/go-secret-envelope.svg)](https://pkg.go.dev/github.com/faustbrian/go-secret-envelope)
[![Release](https://img.shields.io/github/v/release/faustbrian/go-secret-envelope?sort=semver)](https://github.com/faustbrian/go-secret-envelope/releases)
[![Go](https://img.shields.io/badge/go-1.26.6-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`secret-envelope` encrypts application-owned secret payloads with one-use
AES-256-GCM data keys and delegates key wrapping to an explicit provider. The
provider-neutral keyring adapter wraps those keys with versioned AES-256 keys
delivered through an application's secret-management boundary. The optional
AWS KMS adapter uses `GenerateDataKey` and `Decrypt` and also exposes a
verify-only asymmetric KMS boundary for bounded externally signed raw
statements. During `Service` operations, transferred plaintext data keys are
best-effort zeroized before the call returns.

The module is active and stable at v1. It requires Go 1.26.6.

## Install

```sh
go get github.com/faustbrian/go-secret-envelope@v1.0.0
```

The root v1 module currently contains all three public packages:

| Package | Select it when |
| --- | --- |
| `github.com/faustbrian/go-secret-envelope` | You need the envelope format, authenticated context, and `KeyProvider` contract. |
| `github.com/faustbrian/go-secret-envelope/adapters/keyring` | Wrapping keys are delivered to the process by an approved secret manager. |
| `github.com/faustbrian/go-secret-envelope/adapters/awskms` | AWS KMS generates and unwraps data keys or verifies externally signed statements. |

Because the AWS KMS adapter was released inside the root module, installing the
root currently includes the AWS SDK dependencies even when an application uses
only the provider-neutral package or keyring adapter.

## Boundary

Use this module for bounded application payloads persisted in databases or
object storage. Deliver static service credentials and keyring material through
the application's approved secret manager. The module does not manage secret
delivery, rotation workflows, authorization, persistence records, cloud
policies, or logging.

Signature verification authenticates an exact message, key, and reviewed
algorithm. It does not decide whether the signer may approve an action, fetch
signed statements, or expose a signing operation.

Encryption context is mandatory and authenticated by both AES-GCM and the key
provider. Context values are non-secret because AWS KMS can expose them in
CloudTrail. Bind each payload to stable identifiers such as service, owner,
record, and field.

## Example

```go
awsConfig, err := config.LoadDefaultConfig(ctx)
if err != nil {
    return err
}
kmsProvider, err := awskms.New(kms.NewFromConfig(awsConfig))
if err != nil {
    return err
}
envelopes, err := secretenvelope.NewService(kmsProvider)
if err != nil {
    return err
}
binding, err := secretenvelope.NewContext(map[string]string{
    "service":   "location",
    "source_id": sourceID,
    "field":     "vendor_metadata",
})
if err != nil {
    return err
}
encrypted, err := envelopes.Encrypt(ctx, secretenvelope.EncryptRequest{
    Plaintext:    canonicalMetadata,
    KeyReference: kmsKeyARN,
    Context:      binding,
})
if err != nil {
    return err
}
persisted, err := encrypted.MarshalBinary()
```

Applications must load AWS configuration with the SDK default credential
chain. Static credentials are not required by this module.

For secret-manager-delivered wrapping keys, construct a versioned keyring:

```go
keyProvider, err := keyring.New(map[string][]byte{
    "metadata-v1": decodedVersionOneKey,
    "metadata-v2": decodedVersionTwoKey,
})
if err != nil {
    return err
}
envelopes, err := secretenvelope.NewService(keyProvider)
```

Applications select the active reference for new writes and retain every older
key until no persisted envelope refers to it. Keyring values must come from the
approved secret-delivery boundary and must never be committed or logged.

For externally signed statements, construct a verify-only boundary:

```go
verifier, err := awskms.NewSignatureVerifier(
    kms.NewFromConfig(awsConfig),
    types.SigningAlgorithmSpecEcdsaSha256,
)
if err != nil {
    return err
}
if err := verifier.Verify(
    ctx,
    approvalKeyARN,
    canonicalStatement,
    signature,
); err != nil {
    return err
}
```

## Guarantees

- AES-256-GCM with fresh 96-bit nonces from `crypto/rand` by default. The
  `WithNonceReader` test seam transfers nonce uniqueness to the supplied reader.
- A fresh data key for every encrypted payload produced by the bundled keyring
  and AWS KMS providers. Custom `KeyProvider` implementations own that policy.
- Stable, bounded, versioned binary persistence format.
- Immutable contexts and envelopes with caller-owned byte copies.
- Redacted text, JSON, and `slog` representations.
- Plaintext payloads bounded to 4 MiB, with bounded wrapped keys, contexts, and
  envelopes.
- Secret-safe `Error()` text and `%v`/`%+v` formatting that retain `errors.Is`
  cause traversal. Avoid Go-syntax `%#v` formatting of concrete errors because
  it can expose wrapped provider causes.
- Verify-only KMS authentication for raw messages up to 4096 bytes with
  explicit PSS, ECDSA, or Ed25519 algorithms.

## Cancellation boundary

Caller cancellation is observed by providers at their documented boundaries.
After a provider returns successfully, cancellation cannot interrupt the
service's nonce read or bounded local AES-GCM work. Use only the default entropy
source in production; an injected nonce reader is a deterministic-test seam and
must return promptly.

## Documentation

- [Compiler-checked quick start](example_test.go)
- [API and persistence](docs/api.md)
- [Architecture](docs/architecture.md)
- [Security](docs/security.md)
- [Versioned keyrings](docs/keyring.md)
- [AWS KMS operations](docs/aws-kms.md)
- [Compatibility](docs/compatibility.md)
- [Performance](docs/performance.md)
- [FAQ and troubleshooting](docs/faq.md)
- [Specification decisions](docs/specification-decisions.md)
- [Support](SUPPORT.md)
- [Contributing and verification](CONTRIBUTING.md)
- [Release history](CHANGELOG.md)

For ecosystem-wide selection and ownership guidance, see the versioned
[Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.5.3/docs/ecosystem/README.md)
and its [Integration and data movement family](https://github.com/faustbrian/go-library-tools/blob/v1.5.3/docs/ecosystem/design-language.md#package-families-and-selection).

## License

MIT.
