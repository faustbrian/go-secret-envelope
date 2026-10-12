package secretenvelope

import (
	"encoding/binary"
	"errors"
	"sort"
	"unicode/utf8"
)

const (
	maxContextEntries   = 32
	maxContextKeySize   = 256
	maxContextValueSize = 1024
	maxContextSize      = 16 * 1024
)

// ErrInvalidContext reports an empty, malformed or oversized binding context.
var ErrInvalidContext = errors.New("encryption context is invalid")

// Context is immutable, canonical non-secret associated data safe for concurrent
// reads. Its zero value is invalid for cryptographic operations. It does not
// establish trust or authorization for values supplied by the caller.
type Context struct {
	values         map[string]string
	additionalData []byte
}

// NewContext copies 1 through 32 UTF-8 entries with nonempty keys of at most
// 256 bytes, values of at most 1024 bytes (possibly empty), and a canonical
// encoding of at most 16 KiB. Nil/empty input is invalid. Failure returns the
// zero Context and ErrInvalidContext. Bytes remain case-sensitive and are not
// Unicode-normalized; callers must not mutate the map while it is being copied.
func NewContext(values map[string]string) (Context, error) {
	if len(values) == 0 || len(values) > maxContextEntries {
		return Context{}, ErrInvalidContext
	}

	keys := make([]string, 0, len(values))
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		if key == "" ||
			len(key) > maxContextKeySize ||
			len(value) > maxContextValueSize ||
			!utf8.ValidString(key) ||
			!utf8.ValidString(value) {
			return Context{}, ErrInvalidContext
		}
		keys = append(keys, key)
		cloned[key] = value
	}
	// NIST SP 800-38D section 5.2.1.1 accepts AAD but does not define map bytes.
	// Our sorted, length-prefixed encoding makes boundaries unambiguous and
	// independent of map iteration (SECRETENVELOPE-DEC-003;
	// TestContextIsCanonicalAndImmutable).
	sort.Strings(keys)

	additionalData := make([]byte, 0)
	length := make([]byte, 4)
	for _, key := range keys {
		value := cloned[key]
		// #nosec G115 -- admission limits cloned context keys to 256 bytes.
		binary.BigEndian.PutUint32(length, uint32(len(key)))
		additionalData = append(additionalData, length...)
		additionalData = append(additionalData, key...)
		// #nosec G115 -- admission limits cloned context values to 1024 bytes.
		binary.BigEndian.PutUint32(length, uint32(len(value)))
		additionalData = append(additionalData, length...)
		additionalData = append(additionalData, value...)
		if len(additionalData) > maxContextSize {
			return Context{}, ErrInvalidContext
		}
	}

	return Context{
		values:         cloned,
		additionalData: additionalData,
	}, nil
}

// Values returns a caller-owned copy for a key-provider API.
func (encryptionContext Context) Values() map[string]string {
	cloned := make(map[string]string, len(encryptionContext.values))
	for key, value := range encryptionContext.values {
		cloned[key] = value
	}

	return cloned
}

// AdditionalData returns a copy of the canonical sorted key/value bytes, each
// preceded by its uint32 big-endian byte length. The zero Context returns nil.
func (encryptionContext Context) AdditionalData() []byte {
	return append([]byte(nil), encryptionContext.additionalData...)
}

func (encryptionContext Context) valid() bool {
	return len(encryptionContext.values) > 0 &&
		len(encryptionContext.additionalData) > 0
}
