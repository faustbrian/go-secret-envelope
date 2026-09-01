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
