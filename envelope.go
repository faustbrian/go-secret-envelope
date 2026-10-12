package secretenvelope

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"unicode"
	"unicode/utf8"
)

const (
	// DataKeySize is the 32-byte AES-256 data-key length.
	DataKeySize = 32
	// NonceSize is the 12-byte GCM nonce length in the version 1 profile.
	NonceSize = 12
	// MaxPlaintextSize bounds Encrypt payloads to 4 MiB.
	MaxPlaintextSize             = 4 << 20
	maxKeyReferenceSize          = 2048
	maxEncryptedDataKeySize      = 64 << 10
	envelopeHeaderSize           = 17
	minimumEnvelopeSize          = envelopeHeaderSize + 1 + 1 + NonceSize + 16
	envelopeVersion         byte = 1
	algorithmAES256GCM      byte = 1
	envelopeMagic                = "SEV1"
	redacted                     = "[REDACTED]"
	// MaxEnvelopeSize bounds complete SEV1 binary input, including metadata,
	// wrapped key, nonce and the 16-byte GCM tag. It is not a provider blob limit.
	MaxEnvelopeSize = envelopeHeaderSize +
		maxKeyReferenceSize +
		maxEncryptedDataKeySize +
		NonceSize +
		MaxPlaintextSize +
		16
)

// ErrInvalidEnvelope reports malformed framing or invalid data-key material;
// structural acceptance alone does not establish cryptographic authentication.
var ErrInvalidEnvelope = errors.New("secret envelope is invalid")

// Envelope is an immutable encrypted payload and wrapped data key, safe for
// concurrent reads. Its zero value has no usable binary representation.
// A parsed Envelope is only structurally admitted; Service.Decrypt authenticates
// it against the expected Context and the provider's wrapping-key contract.
// Text/Go-syntax/JSON/slog output is redacted; MarshalBinary exposes persistence
// bytes deliberately, and KeyReference deliberately exposes non-secret routing.
type Envelope struct {
	keyReference     string
	encryptedDataKey []byte
	nonce            []byte
	ciphertext       []byte
}

// KeyReference identifies the wrapping key without exposing plaintext.
func (envelope Envelope) KeyReference() string {
	return envelope.keyReference
}

// Ciphertext returns a copy of the payload ciphertext and GCM tag. Calling it
// does not authenticate a parsed envelope; the zero Envelope returns nil.
func (envelope Envelope) Ciphertext() []byte {
	return append([]byte(nil), envelope.ciphertext...)
}

// EncryptedDataKey returns a caller-owned copy of the wrapped data key.
func (envelope Envelope) EncryptedDataKey() []byte {
	return append([]byte(nil), envelope.encryptedDataKey...)
}

// String returns [REDACTED], never encoded envelope bytes.
func (Envelope) String() string { return redacted }

// GoString redacts the Go-syntax representation, including key routing.
func (Envelope) GoString() string { return redacted }

// LogValue prevents envelope bytes and key references from entering slog.
func (Envelope) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

// MarshalJSON emits the JSON string "[REDACTED]". It is not a persistence
// format; use MarshalBinary for deliberate envelope storage.
func (Envelope) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// MarshalBinary returns a new SEV1 version 1, algorithm 1 byte slice: a
// 17-byte big-endian-length header followed by key reference, wrapped key,
// nonce and ciphertext/tag. Invalid or zero values return nil and
// ErrInvalidEnvelope. This validates structure, not authenticity.
// SECRETENVELOPE-DEC-002/004 own this private framing and its limits; see
// TestEnvelopeAcceptsExactSizeLimits and FuzzParseEnvelope.
func (envelope Envelope) MarshalBinary() ([]byte, error) {
	if !envelope.valid() {
		return nil, ErrInvalidEnvelope
	}

	encoded := make([]byte, envelope.encodedSize())
	copy(encoded[:4], envelopeMagic)
	encoded[4] = envelopeVersion
	encoded[5] = algorithmAES256GCM
	// #nosec G115 -- valid() limits key references to 2048 bytes.
	binary.BigEndian.PutUint16(encoded[6:8], uint16(len(envelope.keyReference)))
	binary.BigEndian.PutUint32(
		encoded[8:12],
		// #nosec G115 -- valid() limits wrapped keys to 65536 bytes.
		uint32(len(envelope.encryptedDataKey)),
	)
	// #nosec G115 -- valid() requires the nonce to be exactly 12 bytes.
	encoded[12] = byte(len(envelope.nonce))
	// #nosec G115 -- valid() limits ciphertext to MaxPlaintextSize+16 bytes.
	binary.BigEndian.PutUint32(encoded[13:17], uint32(len(envelope.ciphertext)))
	offset := envelopeHeaderSize
	offset += copy(encoded[offset:], envelope.keyReference)
	offset += copy(encoded[offset:], envelope.encryptedDataKey)
	offset += copy(encoded[offset:], envelope.nonce)
	copy(encoded[offset:], envelope.ciphertext)

	return encoded, nil
}

// ParseEnvelope structurally validates and copies SEV1 version 1 bytes. It
// rejects nil, truncation, trailing bytes, unsupported version/algorithm and
// inconsistent or oversized fields with a zero Envelope and ErrInvalidEnvelope.
// Key references are nonempty UTF-8 without controls (at most 2048 bytes);
// wrapped keys are 1 through 65536 bytes, nonces exactly NonceSize, and
// ciphertext/tag 16 through MaxPlaintextSize+16 bytes. Input is not retained.
// Success does not authenticate: call Service.Decrypt with a trusted expected
// Context before accepting the plaintext or interpreting metadata as trusted.
func ParseEnvelope(encoded []byte) (Envelope, error) {
	if len(encoded) < minimumEnvelopeSize ||
		len(encoded) > MaxEnvelopeSize ||
		string(encoded[:4]) != envelopeMagic ||
		encoded[4] != envelopeVersion ||
		encoded[5] != algorithmAES256GCM {
		return Envelope{}, ErrInvalidEnvelope
	}

	// Compute the complete declared size in uint64 before slicing or copying.
	// Header widths can represent much larger fields than this profile accepts
	// (SECRETENVELOPE-DEC-004; TestEnvelopeRejectsInvalidFieldsAndEncodings).
	keyReferenceSize := uint64(binary.BigEndian.Uint16(encoded[6:8]))
	encryptedDataKeySize := uint64(binary.BigEndian.Uint32(encoded[8:12]))
	nonceSize := uint64(encoded[12])
	ciphertextSize := uint64(binary.BigEndian.Uint32(encoded[13:17]))
	totalSize := uint64(envelopeHeaderSize) +
		keyReferenceSize +
		encryptedDataKeySize +
		nonceSize +
		ciphertextSize
	if totalSize != uint64(len(encoded)) ||
		keyReferenceSize > maxKeyReferenceSize ||
		encryptedDataKeySize > maxEncryptedDataKeySize ||
		nonceSize != NonceSize ||
		ciphertextSize > MaxPlaintextSize+16 {
		return Envelope{}, ErrInvalidEnvelope
	}

	offset := envelopeHeaderSize
	keyReferenceLength := int(keyReferenceSize)
	encryptedDataKeyLength := int(encryptedDataKeySize)
	nonceLength := int(nonceSize)
	envelope := Envelope{
		keyReference: string(encoded[offset : offset+keyReferenceLength]),
	}
	offset += keyReferenceLength
	envelope.encryptedDataKey = append(
		[]byte(nil),
		encoded[offset:offset+encryptedDataKeyLength]...,
	)
	offset += encryptedDataKeyLength
	envelope.nonce = append([]byte(nil), encoded[offset:offset+nonceLength]...)
	offset += nonceLength
	envelope.ciphertext = append([]byte(nil), encoded[offset:]...)
	if !envelope.valid() {
		return Envelope{}, ErrInvalidEnvelope
	}

	return envelope, nil
}

func (envelope Envelope) encodedSize() int {
	return envelopeHeaderSize +
		len(envelope.keyReference) +
		len(envelope.encryptedDataKey) +
		len(envelope.nonce) +
		len(envelope.ciphertext)
}

func (envelope Envelope) valid() bool {
	return validKeyReference(envelope.keyReference) &&
		len(envelope.encryptedDataKey) > 0 &&
		len(envelope.encryptedDataKey) <= maxEncryptedDataKeySize &&
		len(envelope.nonce) == NonceSize &&
		len(envelope.ciphertext) >= 16 &&
		len(envelope.ciphertext) <= MaxPlaintextSize+16 &&
		envelope.encodedSize() <= MaxEnvelopeSize
}

func validKeyReference(value string) bool {
	if value == "" ||
		len(value) > maxKeyReferenceSize ||
		!utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}

	return true
}
