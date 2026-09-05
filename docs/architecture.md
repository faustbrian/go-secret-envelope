# Architecture

The root package owns authenticated local encryption, immutable context,
versioned framing, limits, redaction, and the key-provider contract. It has no
cloud SDK import. The released root v1 module also contains the AWS KMS adapter,
so its `go.mod` necessarily includes the AWS SDK even when a consumer imports
only the root package or keyring adapter. Extracting that released package into
a nested module requires separate compatibility and consumer evidence; it is
not an implicit documentation-only change.

`adapters/keyring` owns in-process data-key wrapping with an immutable set of
versioned AES-256 keys supplied by the application. It authenticates the exact
key reference and canonical context, generates a fresh data key and wrapping
nonce for each encryption, and retains no secret-manager client dependency.

`adapters/awskms` owns AWS SDK request and response mapping. It requests
`AES_256`, passes the exact non-secret encryption context to both KMS
operations, stores the resolved key ARN returned by KMS, and specifies that
exact key during decryption. Its separate signature verifier owns a
least-privilege `kms:Verify` surface, fixes one reviewed asymmetric algorithm,
uses raw-message mode, and exposes no signing method.

Applications own canonical plaintext serialization, authorization,
transactions, fingerprints, row lifecycle, secret delivery, provider policy,
and rotation orchestration. Signature consumers also own canonical statement
encoding, signer-to-role authorization, replay policy, and signed-statement
storage. Secret managers remain deployment boundaries; they are not used as
per-row persistence substitutes.

The packages create no goroutines, timers, connections, or background cleanup.
Applications own injected providers and clients, their transports and retry
configuration, and any external resource shutdown.
