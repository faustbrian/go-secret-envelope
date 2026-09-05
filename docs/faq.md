# Frequently asked questions

## Is encryption context secret?

No. Context is authenticated associated data and AWS KMS can record it in
CloudTrail. Use stable service, owner, record, and field identifiers; never put
credentials or payload data in it.

## Does the module deliver or rotate keys?

No. Applications deliver wrapping keys or AWS credentials, choose the active
key reference for new writes, retain old keys while envelopes reference them,
and own rotation and authorization policy.

## Can a service be shared between goroutines?

Only when its `KeyProvider` and nonce reader support concurrent calls. The
default `crypto/rand.Reader` and bundled keyring provider do. AWS providers and
signature verifiers inherit concurrency guarantees from their injected
clients.

## Why does a keyring-only application download the AWS SDK?

The AWS KMS adapter was released inside the root v1 module, so AWS SDK modules
remain in the root dependency graph. Extracting the adapter can change module
resolution and requires a separate compatibility and release plan.

## Does zeroization guarantee that keys leave memory?

No. Service-managed plaintext data keys are overwritten on a best-effort basis,
but Go may retain compiler, stack, runtime, or garbage-collector copies.
Keyring wrapping keys remain in process memory for the provider lifetime.

## Does the module own retries, deadlines, or cleanup?

No. Operations use caller contexts, adapters add no retry or deadline, and the
packages create no background work or long-lived resources requiring shutdown.
AWS SDK client policy and resource cleanup remain caller-owned.

After a provider returns successfully, cancellation cannot interrupt an
injected nonce read or the bounded local AES-GCM operation. The default
`crypto/rand.Reader` is required for production security, but its read is also
outside context cancellation and has no package-level prompt-return guarantee.
`WithNonceReader` is a deterministic-test seam; a blocked injected reader can
therefore block `Encrypt` after the provider has completed even if the caller
cancels its context.

## Troubleshooting

### An operation returned after its context deadline

The provider observes the caller context at its documented boundary, but local
AES-GCM work is not interruptible once it starts. For `Encrypt`, an injected
nonce reader also receives no context. Use `crypto/rand.Reader` in production,
ensure test readers return promptly, account for the nonce read outside the
context deadline, and include the bounded local work in the caller's total
deadline budget.

### An encrypted payload no longer decrypts

Confirm that the exact persisted key reference still exists, the expected
context is byte-for-byte equivalent after canonicalization, and the envelope is
complete and unmodified. Do not fall back to another key or context. A missing
reference is a rotation or custody problem; an authentication failure means the
key, context, nonce, ciphertext, or tag does not match.

### AWS KMS rejects or times out

Check the persisted resolved key ARN, region, `kms:GenerateDataKey` or
`kms:Decrypt` permission, encryption context, SDK retry policy, HTTP transport,
and caller deadline. The adapter neither retries nor adds a timeout. Repository
tests use injected clients and do not prove live AWS connectivity or IAM.

### How should an operation failure be classified?

Use `errors.Is` or `errors.As` against the stable categories documented in the
[API guide](api.md); do not branch on error text. Invalid request or envelope
errors indicate local input or persisted-format problems. Provider and KMS
errors retain a cause for programmatic inspection, while authentication errors
mean the key, context, nonce, ciphertext, or signature did not authenticate.
Log the stable error category and non-secret operation metadata, never keys,
plaintext, credentials, ciphertext, signatures, or Go-syntax `%#v` errors.

For disclosure and credential-handling incidents, follow the repository
[security policy](../SECURITY.md). For usage questions and defect reports, see
[support](../SUPPORT.md).
