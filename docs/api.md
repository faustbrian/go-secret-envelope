# API and persistence

`NewContext` creates immutable, canonically ordered non-secret associated data.
`NewService` requires a `KeyProvider` and defaults nonce generation to
`crypto/rand.Reader`. `Encrypt` returns an immutable `Envelope`; `Decrypt`
requires the exact expected context.

## Construction and ownership

`NewContext` copies the input map. `Context.Values`, `Context.AdditionalData`,
`Envelope.Ciphertext`, and `Envelope.EncryptedDataKey` return caller-owned
copies. `ParseEnvelope` copies every retained byte field from its input.

`Encrypt` borrows the request plaintext for the duration of the call. It does
not retain, mutate, or zeroize that caller-owned payload. On successful
construction, `NewDataKey` transfers its plaintext and wrapped-key byte slices
to the returned value. On nil-error returns, a `KeyProvider` transfers a
generated plaintext data key or decrypted plaintext key to its caller. On
error, the provider must return no secret output and remains responsible for
clearing secret bytes it produced. When the caller is `Service`, the service
best-effort zeroizes a successfully transferred key before returning.
The decrypted payload returned by `Decrypt` is caller-owned. A direct caller of
`DecryptDataKey` owns and must clear the returned plaintext key when finished.
A direct caller of `GenerateDataKey` owns the returned `DataKey`, whose private
plaintext remains until Go reclaims it because no public destruction operation
exists; normal consumers should invoke providers through `Service`.

`WithNonceReader` is a deterministic-test seam. The service retains the supplied
reader for its lifetime; the caller must keep it usable, preserve nonce
uniqueness, make concurrent access safe, and ensure reads return promptly. The
reader receives no context, so caller cancellation cannot interrupt a blocked
read. Options are applied in order, so the last nonce-reader option wins.

The service starts no goroutines or timers, acquires no connections, and has no
`Close` or `Shutdown` operation. It retains its provider and nonce reader but
does not own their external resources. A service may be used concurrently only
when its provider and nonce reader support concurrent calls. The default
`crypto/rand.Reader` and the bundled keyring provider support concurrent use.
The AWS KMS provider and signature verifier inherit concurrency guarantees from
their injected clients.

## Context, failures, and retries

Every provider operation accepts the caller's context. The service forwards it
without adding a deadline or retry. The keyring provider rejects an already
canceled context before local cryptographic work, but that bounded local work
is not interruptible once started. AWS operations pass the context to the
injected client. The signature verifier also rejects an already canceled
context before invoking that client. AWS SDK retry and timeout configuration is
owned by the caller-created client; the adapters add neither retries nor a
detached work budget. If an injected KMS client returns an error together with
a response, that client retains responsibility for the response and any secret
bytes; the adapter does not inspect error responses.

After a provider returns successfully, canceling the context cannot interrupt
the nonce read or bounded local AES-GCM work. The default `crypto/rand.Reader`
is required for production security, but its read is also outside context
cancellation and carries no package-level prompt-return guarantee. A
deterministic test reader must return promptly. Local encryption and decryption
are not interruptible once started.

Stable root failure categories include invalid service/request/envelope/context,
provider failure, entropy failure, and authentication failure. Keyring failures
distinguish invalid configuration/request, missing references, entropy, and
authentication. AWS envelope failures distinguish missing clients, invalid
requests, KMS operations, and invalid responses. Signature verification
distinguishes invalid construction/request, operational KMS failure, an
authenticated rejection, and an invalid response. Wrapped provider causes
remain available to `errors.Is` and `errors.As`. `Error()`, `%v`, and `%+v`
formatting do not render those causes. Callers must not use Go-syntax `%#v`
formatting on concrete root or AWS data-key operation errors when a provider
cause may contain sensitive data. Signature-operation errors explicitly redact
every formatting verb.

`Envelope.MarshalBinary` and `ParseEnvelope` own the stable persistence format:

1. `SEV1` magic;
2. version and AES-256-GCM algorithm identifiers;
3. bounded key-reference, wrapped-key, nonce, and ciphertext lengths; and
4. the corresponding bytes.

Plaintext is limited to 4 MiB. The encoded-envelope limit derives from that
bound plus the versioned header, key reference, wrapped key, nonce, and GCM
authentication tag.

The key reference is duplicated in the database as an operator-visible field
when applications require rotation and custody audits. The encoded envelope
keeps its own copy so moving ciphertext without its exact wrapping key is
rejected.

## Versioned keyring provider

`keyring.New` copies one to 32 versioned 32-byte wrapping keys. New encryption
selects an explicit reference; decryption selects the exact reference embedded
in the envelope. The provider authenticates the reference and canonical
context while wrapping each fresh data key with AES-256-GCM.

The application owns decoding secret-manager values, selecting the active
reference, retaining historical keys, and rolling out rotation. Removing a key
while persisted ciphertext still references it makes that ciphertext
unreadable.

The provider copies the input map and every wrapping key. It retains those
copies in process memory for its lifetime and has no explicit destruction or
shutdown operation. Their eventual reclamation is controlled by the Go
runtime; it is not a zeroization guarantee.

The format is not JSON. JSON, text, Go-syntax, and `slog` representations are
redacted. Encrypted bytes are not plaintext secrets, but exposing them still
increases offline attack and operational risk.

## AWS KMS signature verification

`awskms.NewSignatureVerifier` fixes one reviewed signing algorithm for the
verifier lifetime. `Verify` accepts an explicit KMS key reference, one non-empty
raw message of at most 4096 bytes, and one bounded signature. It copies caller
bytes before calling KMS and never exposes a signing operation.

Accepted raw-message algorithms are RSASSA-PSS SHA-256/384/512, ECDSA
SHA-256/384/512, and Ed25519 SHA-512. PKCS#1 v1.5, digest-mode, SM2, ML-DSA,
and implicit algorithm selection are rejected.

`ErrSignatureRejected` is an authenticated negative result.
`ErrKMSSignatureVerification` is an operational KMS failure.
`ErrInvalidSignatureResponse` rejects incomplete or contradictory successful
responses. Wrapped causes remain available to `errors.Is` and `errors.As`, but
formatted errors never render them.
