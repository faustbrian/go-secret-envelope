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
	ErrServiceRequired = errors.New("secret envelope service is required")
	ErrKeyProvider     = errors.New("secret envelope key provider failed")
	ErrInvalidRequest  = errors.New("secret envelope request is invalid")
	ErrEntropy         = errors.New("secret envelope nonce generation failed")
	ErrAuthentication  = errors.New("secret envelope authentication failed")
)

// DataKey owns wrapped and plaintext key bytes returned by a KeyProvider. Its
// plaintext is not publicly accessible. Service zeroizes it after managed use;
// direct provider callers cannot explicitly clear it and should use Service.
type DataKey struct {
	plaintext    []byte
	ciphertext   []byte
	keyReference string
}

func (DataKey) String() string   { return redacted }
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
// ownership of them to the returned data key.
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
	GenerateDataKey(context.Context, string, Context) (DataKey, error)
	DecryptDataKey(context.Context, string, []byte, Context) ([]byte, error)
}

// EncryptRequest carries caller-owned plaintext borrowed for one Encrypt call
// and its immutable non-secret binding context.
type EncryptRequest struct {
	Plaintext    []byte
	KeyReference string
	Context      Context
}

// DecryptRequest carries an immutable envelope and its expected immutable
// non-secret binding context.
type DecryptRequest struct {
	Envelope Envelope
	Context  Context
}

type serviceOptions struct {
	nonceReader io.Reader
}

// Option configures a Service without introducing ambient state.
type Option func(*serviceOptions) error

// WithNonceReader replaces crypto/rand for deterministic tests. Service retains
// the reader; callers must preserve nonce uniqueness, and concurrent callers
// require a reader that supports concurrent use. Reads receive no context and
// must return promptly: canceling the Encrypt context cannot interrupt a
// blocked read. When repeated, the last option wins.
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
// provider and nonce reader to support concurrent calls.
type Service struct {
	provider    KeyProvider
	nonceReader io.Reader
}

// NewService validates and retains explicit key and entropy dependencies.
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
// those stable categories; provider failures wrap ErrKeyProvider and retain
// their cause. After the provider returns, canceling ctx cannot interrupt the
// nonce read or local AES-GCM encryption. Concurrent calls require
// concurrent-safe Service dependencies.
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
			cause:     err,
		}
	}
	defer zero(dataKey.plaintext)
	if len(dataKey.plaintext) != DataKeySize ||
		len(dataKey.ciphertext) == 0 ||
		len(dataKey.ciphertext) > maxEncryptedDataKeySize ||
		!validKeyReference(dataKey.keyReference) {
		return Envelope{}, ErrInvalidEnvelope
	}

	block, _ := aes.NewCipher(dataKey.plaintext)
	authenticatedCipher, _ := cipher.NewGCM(block)
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(service.nonceReader, nonce); err != nil {
		zero(nonce)
		return Envelope{}, operationError{
			operation: "encrypt",
			kind:      ErrEntropy,
			cause:     err,
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
// categories; provider failures wrap ErrKeyProvider and retain their cause.
// After the provider returns, canceling ctx cannot interrupt local AES-GCM
// decryption. Concurrent calls require concurrent-safe Service dependencies.
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
			cause:     err,
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

func (err operationError) Error() string {
	return "secret envelope " + err.operation + " failed"
}

func (err operationError) Unwrap() []error {
	return []error{err.kind, err.cause}
}

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
