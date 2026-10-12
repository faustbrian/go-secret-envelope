package secretenvelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"reflect"

	"encoding/json"
)

var (
	// ErrServiceRequired reports a nil/zero Service or missing provider/entropy dependency.
	ErrServiceRequired = errors.New("secret envelope service is required")
	// ErrKeyProvider classifies a provider failure; only safe context cancellation/deadline
	// categories, not the provider cause, are retained in the error chain.
	ErrKeyProvider = errors.New("secret envelope key provider failed")
	// ErrInvalidRequest reports a nil context or invalid payload, reference, binding or option.
	ErrInvalidRequest = errors.New("secret envelope request is invalid")
	// ErrEntropy classifies nonce-read failure without preserving reader diagnostics.
	ErrEntropy = errors.New("secret envelope nonce generation failed")
	// ErrAuthentication reports failure to authenticate the payload ciphertext and context.
	ErrAuthentication = errors.New("secret envelope authentication failed")
)

// DataKey owns wrapped and plaintext key bytes returned by a KeyProvider. Its
// plaintext is not publicly accessible. Service best-effort clears it after use;
// direct provider callers cannot explicitly clear it and should use Service.
// Copying DataKey shares its transferred byte storage, not independent key
// ownership. Once transferred, callers must not mutate those slices or reuse the
// key for another encryption. The zero DataKey is invalid cryptographic material.
type DataKey struct {
	plaintext    []byte
	ciphertext   []byte
	keyReference string
}

// String returns [REDACTED], never key bytes.
func (DataKey) String() string { return redacted }

// GoString redacts the Go-syntax representation of all key material.
func (DataKey) GoString() string { return redacted }

// LogValue prevents data-key material from entering slog.
func (DataKey) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

// MarshalJSON prevents accidental JSON disclosure of data-key material.
func (DataKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// NewDataKey validates key-provider response bytes and, on success, transfers
// ownership of them to the returned data key, without copying or assessing
// entropy quality. Plaintext must be DataKeySize bytes, wrapped bytes 1 through
// 65536 bytes, and the reference nonempty UTF-8 without controls, at most 2048
// bytes. Failure returns the zero DataKey and ErrInvalidEnvelope, leaves inputs
// untouched, and leaves their cleanup to the caller.
func NewDataKey(
	plaintext []byte,
	ciphertext []byte,
	keyReference string,
) (DataKey, error) {
	if len(plaintext) != DataKeySize ||
		len(ciphertext) == 0 ||
		len(ciphertext) > maxEncryptedDataKeySize ||
		!validKeyReference(keyReference) {
		return DataKey{}, ErrInvalidEnvelope
	}

	return DataKey{
		plaintext:    plaintext,
		ciphertext:   ciphertext,
		keyReference: keyReference,
	}, nil
}

// KeyReference identifies the wrapping key without exposing plaintext.
func (dataKey DataKey) KeyReference() string {
	return dataKey.keyReference
}

// EncryptedDataKey returns a caller-owned copy of the wrapped key.
func (dataKey DataKey) EncryptedDataKey() []byte {
	return append([]byte(nil), dataKey.ciphertext...)
}

// KeyProvider wraps and unwraps one-use AES-256 data keys. Its methods receive
// the caller's context and borrow call arguments only for the operation. On a
// nil-error return, they transfer the returned DataKey or plaintext bytes to the
// caller. On error, they must return no secret output and remain responsible for
// clearing any internally produced secret bytes. Service wraps provider errors
// with ErrKeyProvider. Concurrent Service use requires a provider that supports
// concurrent calls.
type KeyProvider interface {
	// GenerateDataKey returns a fresh unpredictable DataKey for one payload,
	// wrapping it under the requested/resolved reference and binding Context.
	// Success transfers exclusive key-byte ownership; failure returns no key
	// and the provider must clear any secret bytes it created.
	GenerateDataKey(context.Context, string, Context) (DataKey, error)
	// DecryptDataKey authenticates wrapped bytes under the exact reference and
	// Context, returning exactly DataKeySize owned plaintext bytes on success.
	// Ciphertext is borrowed only for this call; failure returns no plaintext.
	DecryptDataKey(context.Context, string, []byte, Context) ([]byte, error)
}

// EncryptRequest carries caller-owned plaintext borrowed for one Encrypt call
// and its immutable non-secret binding context. Unlike Envelope/DataKey, this
// request has no redacting formatter: do not log or JSON-encode plaintext requests.
type EncryptRequest struct {
	// Plaintext is 1 through MaxPlaintextSize bytes, borrowed for this call.
	// Service does not retain, mutate or clear it; do not mutate concurrently.
	Plaintext []byte
	// KeyReference selects the provider wrapping key; it is nonempty UTF-8,
	// without controls, at most 2048 bytes. Providers may impose stricter rules.
	KeyReference string
	// Context binds trusted non-secret record identity and purpose. Its zero
	// value is invalid; values are authenticated, not encrypted.
	Context Context
}

// DecryptRequest carries an immutable envelope and its expected immutable
// non-secret binding context.
type DecryptRequest struct {
	// Envelope is the structurally valid encrypted payload to authenticate.
	Envelope Envelope
	// Context is the trusted expected binding, not context copied from an
	// untrusted record. It must match the encryption context exactly.
	Context Context
}

type serviceOptions struct {
	nonceReader io.Reader
}

// Option configures NewService in call order without ambient state. Nil options
// are invalid; options are applied only during construction.
type Option func(*serviceOptions) error

// WithNonceReader replaces crypto/rand for deterministic tests. Service retains
// the reader; callers must preserve nonce uniqueness, and concurrent callers
// require a reader that supports concurrent use. Reads receive no context and
// must return promptly: canceling the Encrypt context cannot interrupt a
// blocked read. When repeated, the last option wins. Nil or typed-nil readers
// return ErrInvalidRequest during construction. This option does not copy, close
// or serialize the reader and does not make deterministic entropy production-safe.
func WithNonceReader(reader io.Reader) Option {
	return func(options *serviceOptions) error {
		if nilLike(reader) {
			return ErrInvalidRequest
		}
		options.nonceReader = reader

		return nil
	}
}

// Service performs local AES-256-GCM operations around a key provider. It owns
// no external resources or background work. Concurrent use requires the
// provider and nonce reader to support concurrent calls. The zero Service is
// not ready for use; there is no Close or destruction method. Callers own
// provider/reader shutdown and plaintext payload cleanup. Collaborator panics
// are not recovered by Service.
type Service struct {
	provider    KeyProvider
	nonceReader io.Reader
}

// NewService retains the provider and defaults nonce reads to crypto/rand.Reader.
// Nil/typed-nil providers return nil and ErrServiceRequired; invalid options
// return nil and their error. Construction creates no external resources.
func NewService(provider KeyProvider, options ...Option) (*Service, error) {
	if nilLike(provider) {
		return nil, ErrServiceRequired
	}
	settings := serviceOptions{nonceReader: rand.Reader}
	for _, option := range options {
		if option == nil {
			return nil, ErrInvalidRequest
		}
		if err := option(&settings); err != nil {
			return nil, err
		}
	}

	return &Service{
		provider:    provider,
		nonceReader: settings.nonceReader,
	}, nil
}

// Encrypt borrows the request plaintext for this call, forwards ctx to the
// provider without adding a deadline or retry, and best-effort zeroizes the
// transferred plaintext data key before returning. It returns
// ErrServiceRequired, ErrInvalidRequest, ErrInvalidEnvelope, or ErrEntropy for
// those stable categories. Provider failures wrap ErrKeyProvider and retain only
// context cancellation or deadline categories. After the provider returns,
// canceling ctx cannot interrupt the nonce read or local AES-GCM encryption.
// Failure returns a zero Envelope, never partial ciphertext. Plaintext is
// nonempty; the Envelope owns ciphertext, nonce and copied wrapped-key bytes.
// Context is authenticated but not stored in the envelope. The
// provider must supply a fresh key and authenticate wrapping metadata; Service
// cannot verify provider entropy quality, replay policy or caller authorization.
// Concurrent calls require concurrent-safe dependencies.
func (service *Service) Encrypt(
	ctx context.Context,
	request EncryptRequest,
) (Envelope, error) {
	if service == nil ||
		nilLike(service.provider) ||
		nilLike(service.nonceReader) {
		return Envelope{}, ErrServiceRequired
	}
	if ctx == nil ||
		len(request.Plaintext) == 0 ||
		len(request.Plaintext) > MaxPlaintextSize ||
		!validKeyReference(request.KeyReference) ||
		!request.Context.valid() {
		return Envelope{}, ErrInvalidRequest
	}

	dataKey, err := service.provider.GenerateDataKey(
		ctx,
		request.KeyReference,
		request.Context,
	)
	if err != nil {
		return Envelope{}, operationError{
			operation: "encrypt",
			kind:      ErrKeyProvider,
			cause:     safeErrorCause(err),
		}
	}
	// Clear the successfully transferred key on every later exit, including
	// invalid provider material and nonce failure (SECRETENVELOPE-DEC-006;
	// TestServiceRejectsInvalidKeyMaterialAndEntropy). Provider error paths
	// retain provider cleanup ownership instead.
	defer zero(dataKey.plaintext)
	if len(dataKey.plaintext) != DataKeySize ||
		len(dataKey.ciphertext) == 0 ||
		len(dataKey.ciphertext) > maxEncryptedDataKeySize ||
		!validKeyReference(dataKey.keyReference) {
		return Envelope{}, ErrInvalidEnvelope
	}

	// The length checks fix AES-256, a 96-bit nonce and the default 128-bit GCM
	// tag without negotiation (NIST SP 800-38D, November 2007, sections 5.2/8;
	// FIPS 197, updated May 2023; SECRETENVELOPE-DEC-001). AAD is the canonical
	// context; reference/wrapped-key authentication belongs to KeyProvider.
	block, _ := aes.NewCipher(dataKey.plaintext)
	authenticatedCipher, _ := cipher.NewGCM(block)
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(service.nonceReader, nonce); err != nil {
		zero(nonce)
		return Envelope{}, operationError{
			operation: "encrypt",
			kind:      ErrEntropy,
		}
	}

	return Envelope{
		keyReference:     dataKey.keyReference,
		encryptedDataKey: append([]byte(nil), dataKey.ciphertext...),
		nonce:            nonce,
		ciphertext: authenticatedCipher.Seal(
			nil,
			nonce,
			request.Plaintext,
			request.Context.additionalData,
		),
	}, nil
}

// Decrypt forwards ctx to the provider without adding a deadline or retry,
// best-effort zeroizes the transferred plaintext data key, and returns a
// caller-owned plaintext payload. It returns ErrServiceRequired,
// ErrInvalidRequest, ErrInvalidEnvelope, or ErrAuthentication for those stable
// categories. Provider failures wrap ErrKeyProvider and retain only context
// cancellation or deadline categories.
// After the provider returns, canceling ctx cannot interrupt local AES-GCM
// decryption. Failure returns nil plaintext. Successful plaintext is not cleared
// by Service: its lifecycle belongs to the caller. A structurally admitted
// tag-only ciphertext may authenticate an empty payload even though Encrypt
// rejects empty plaintext. Concurrent calls require concurrent-safe dependencies.
func (service *Service) Decrypt(
	ctx context.Context,
	request DecryptRequest,
) ([]byte, error) {
	if service == nil || nilLike(service.provider) {
		return nil, ErrServiceRequired
	}
	if ctx == nil || !request.Envelope.valid() || !request.Context.valid() {
		return nil, ErrInvalidRequest
	}

	plaintextKey, err := service.provider.DecryptDataKey(
		ctx,
		request.Envelope.keyReference,
		request.Envelope.EncryptedDataKey(),
		request.Context,
	)
	if err != nil {
		return nil, operationError{
			operation: "decrypt",
			kind:      ErrKeyProvider,
			cause:     safeErrorCause(err),
		}
	}
	defer zero(plaintextKey)
	if len(plaintextKey) != DataKeySize {
		return nil, ErrInvalidEnvelope
	}

	block, _ := aes.NewCipher(plaintextKey)
	authenticatedCipher, _ := cipher.NewGCM(block)
	plaintext, err := authenticatedCipher.Open(
		nil,
		request.Envelope.nonce,
		request.Envelope.ciphertext,
		request.Context.additionalData,
	)
	if err != nil {
		return nil, ErrAuthentication
	}

	return plaintext, nil
}

type operationError struct {
	operation string
	kind      error
	cause     error
}

// Error returns an operation label without request data or provider error text.
func (err operationError) Error() string {
	return "secret envelope " + err.operation + " failed"
}

// Unwrap exposes the failure category and any retained standard context
// cancellation or deadline sentinel, not the original provider error.
func (err operationError) Unwrap() []error {
	if err.cause == nil {
		return []error{err.kind}
	}

	return []error{err.kind, err.cause}
}

// Retain canonical context categories, not provider errors that may carry
// secret request data. SECRETENVELOPE-DEC-006 and
// TestServicePreservesOnlySafeProviderCancellation protect this error boundary.
func safeErrorCause(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// Overwriting this slice narrows ordinary key lifetime, but does not erase
// expanded cipher keys, compiler/runtime copies or caller-retained aliases.
// This is best-effort cleanup, not a secure-memory guarantee (SE-RISK-003 in
// docs/security.md and SECRETENVELOPE-DEC-006).
func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func nilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
