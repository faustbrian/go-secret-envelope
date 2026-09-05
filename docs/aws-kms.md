# AWS KMS operations

The adapter uses `GenerateDataKey` with `AES_256` and `Decrypt` with
`SYMMETRIC_DEFAULT`. Both calls include the exact case-sensitive encryption
context. When the provider is used through `Service`, the generated plaintext
key is used only for local AES-GCM and then best-effort zeroized; the wrapped
key is stored with the ciphertext. Direct provider-call ownership is described
below.

KMS returns the resolved key ARN. Persist that ARN rather than the input alias
so later alias rotation does not make historical ciphertext ambiguous.

Applications construct the SDK client from `config.LoadDefaultConfig`. This
uses the AWS SDK default credential chain, including web identity in
Kubernetes. The module does not accept or store static AWS credentials.

`awskms.New` borrows and retains the injected client. The application owns the
client's configuration, HTTP transport, retry policy, credentials, and
resources. The provider adds no retry or deadline and starts no background
work. It copies wrapped-key bytes before decryption requests and transfers valid
plaintext data-key response bytes to its caller. `Service` best-effort zeroizes
those bytes after managed use; a direct provider caller owns and must clear
them. A directly generated `DataKey` retains private plaintext until Go
reclaims it because it exposes no destruction operation. Concurrent provider
use requires a client that is safe for concurrent calls.
If an injected client returns an error with a response, the client retains
responsibility for that response and any secret bytes. The provider does not
inspect error responses.

The adapter passes the caller context to the injected client. A KMS request is
time-bounded only when that context or the client configuration supplies a
deadline or timeout. Once KMS returns successfully, canceling the context
cannot interrupt the service's nonce read or bounded local AES-GCM encryption
or decryption. Applications that need a total operation deadline must budget
for both the KMS request and this bounded local work.

## Asymmetric signature verification

`NewSignatureVerifier` exposes only `kms:Verify`; it does not expose `Sign`.
Each verifier fixes one reviewed algorithm. `Verify` sends the exact copied
message with `MessageType=RAW`, the explicit key reference, and the copied
signature. Raw messages are bounded to AWS KMS's 4096-byte limit.

The adapter accepts RSASSA-PSS, ECDSA, and non-prehashed Ed25519 algorithms at
SHA-256 strength or higher. It rejects PKCS#1 v1.5, digest mode, SM2, ML-DSA,
prehashed Ed25519, implicit algorithms, empty resolved keys, algorithm drift,
and false verification responses.

KMS signature verification is logged in CloudTrail. IAM should grant only
`kms:Verify` on the exact asymmetric signing-key ARNs required by the
application. Authorization of a verified signer or key for an application role
remains an application policy decision.

`NewSignatureVerifier` likewise borrows its client for the verifier lifetime.
The verifier copies each message and signature before invoking KMS, starts no
background work, and inherits concurrency support from that client.
