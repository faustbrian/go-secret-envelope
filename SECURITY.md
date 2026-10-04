# Security policy

Report vulnerabilities through a
[private GitHub security advisory](https://github.com/faustbrian/go-secret-envelope/security/advisories/new).
Do not include production ciphertext, plaintext, keys, credentials, customer
data, or KMS identifiers that reveal private topology.

See the shared
[severity, triage and coordinated-disclosure process](https://github.com/faustbrian/go-library-tools/blob/25a69b6357457c1660c4fb25a5302c259070b962/docs/ecosystem/security/vulnerability-management.md).

The module protects local authenticated encryption, persistence framing,
context binding, key-provider adaptation, bounds, and diagnostic redaction. It
does not protect a compromised process, caller-retained plaintext, swap or
crash dumps, insecure transport, incorrect authorization, excessive IAM
permissions, malicious KMS administrators, or application logging of raw
inputs.

The versioned repository threat model, controls, and accepted-risk register are
maintained in [docs/security.md](docs/security.md).

Plaintext data-key zeroization is best effort under Go's memory model. Callers
own plaintext payload lifecycle and must avoid retaining unnecessary copies.
Encryption context is non-secret and can appear in AWS CloudTrail.

Provider failures expose only stable package categories plus safe context
cancellation or deadline identity. Underlying provider errors are discarded
because they can contain credentials, key topology, request data, or other
sensitive diagnostics.
