// Package awskms adapts AWS KMS data-key operations to secret-envelope key
// wrapping and authenticates bounded externally signed raw statements with
// asymmetric KMS keys.
//
// Encryption context values are visible to AWS and CloudTrail. They must
// remain non-secret. Start with New for a KeyProvider or NewSignatureVerifier
// for verify-only statements. Clients are borrowed; callers own credentials,
// transport, retries, deadlines, concurrent-call safety and shutdown. The package
// starts no background work and introduces the AWS SDK, but no cgo.
//
// The request model is pinned to service/kms v1.61.3 at
// c88f24ba4a32e01258202d54f33bc67598b9e041; fixed selections and exact-response
// checks are SECRETENVELOPE-DEC-007 through -010 in docs/specification-decisions.md.
// Synthetic SDK tests do not claim live AWS or independent signature conformance.
// Applications own trusted context, statement canonicalization, key-to-role
// authorization and replay policy; successful KMS verification does not own them.
package awskms
