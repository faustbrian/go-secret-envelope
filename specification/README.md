# Specification Conformance Matrix

[Specification decisions](../docs/specification-decisions.md)

The executable lane proves repository behavior. Empty fixture,
interoperability, and differential lanes mean no official corpus, live
provider, or maintained-peer agreement is claimed. AWS recording-client tests
are bounded to the pinned SDK seam.

NIST release authorities reuse the official stable publication bytes because
the corresponding CSRC HTML release pages contain request-specific transforms
and cannot serve as reproducible content pins. The 90-day review remains
responsible for checking supersession; the online gate detects in-place changes
to the official publication artifacts.

## Upstream review history

### 2026-09-03

- AWS SDK for Go v2 KMS advanced from service/kms v1.55.0 commit
  `4fef3455fe2dcb5ea3de4e9fbacf889b84c8a255` to v1.58.0 commit
  `5a5ee7a736838df1cb7c39f2b3f5d78bed226463`. The reviewed operation-file
  changes move generated transport middleware without changing the request and
  response fields, validation, raw-message bound, or algorithm semantics used
  by the four KMS decisions; the enum source remains byte-identical. The change
  is behavior-neutral for the repository's fixed request, identity, allowlist,
  response-matching, and bounds contracts, so the pinned v1.55.0 source
  bindings remain selected.

| Decision | Sources | Executable evidence | Other evidence |
| --- | --- | --- | --- |
| SECRETENVELOPE-DEC-001 | `nist-sp800-38d-source`, `fips197-source` | `TestServiceEncryptsAndDecryptsAnAuthenticatedEnvelope`, `TestProviderWrapsAndUnwrapsDataKeysByReferenceAndContext` | Not assessed |
| SECRETENVELOPE-DEC-002 | `nist-sp800-38d-source` | `TestServiceEncryptsAndDecryptsAnAuthenticatedEnvelope`, `TestEnvelopeParsingRejectsMalformedOrOversizedInput` | `FuzzParseEnvelope` |
| SECRETENVELOPE-DEC-003 | `nist-sp800-38d-source` | `TestContextIsCanonicalAndImmutable`, `TestServiceRejectsAContextSwap`, `TestProviderAuthenticatesReferenceContextAndCiphertext` | Not assessed |
| SECRETENVELOPE-DEC-004 | `nist-sp800-38d-source` | `TestEnvelopeParsingRejectsMalformedOrOversizedInput`, `TestEnvelopeAcceptsExactSizeLimits` | `FuzzParseEnvelope` |
| SECRETENVELOPE-DEC-005 | `nist-sp800-38d-source` | `TestProviderWrapsAndUnwrapsDataKeysByReferenceAndContext`, `TestProviderUsesExactBoundedWireAllocations` | Not assessed |
| SECRETENVELOPE-DEC-006 | `nist-sp800-38d-source` | `TestServiceRejectsInvalidKeyMaterialAndEntropy`, `TestProviderRejectsEntropyFailures`, `TestProviderRejectsInvalidGenerateResponsesAndZeroizesKeys` | Not assessed |
| SECRETENVELOPE-DEC-007 | `aws-kms-generate-source`, `aws-kms-decrypt-source`, `aws-kms-enums-source` | `TestProviderGeneratesAnAES256DataKey`, `TestProviderDecryptsWithTheExactKeyAndContext` | Not assessed |
| SECRETENVELOPE-DEC-008 | `aws-kms-decrypt-source`, `aws-kms-generate-source`, `aws-kms-enums-source` | `TestProviderGeneratesAnAES256DataKey`, `TestProviderDecryptsWithTheExactKeyAndContext`, `TestProviderRejectsDecryptFailuresAndMalformedResponses` | Not assessed |
| SECRETENVELOPE-DEC-009 | `aws-kms-verify-source`, `aws-kms-enums-source`, `rfc8017-source`, `fips186-5-source`, `rfc8032-source`, `fips180-4-source` | `TestSignatureVerifierAuthenticatesExactRawMessage`, `TestSignatureVerifierAcceptsReviewedRawAlgorithms`, `TestSignatureVerifierRejectsInvalidConstructionAndRequests` | Not assessed |
| SECRETENVELOPE-DEC-010 | `aws-kms-verify-source` | `TestSignatureVerifierAcceptsExactRequestLimits`, `TestSignatureVerifierClassifiesFailuresWithoutRenderingCauses`, `TestSignatureVerifierRejectsInvalidConstructionAndRequests` | Not assessed |
