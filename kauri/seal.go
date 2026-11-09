package kauri

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// MaxRecordPlaintext is the largest record plaintext before padding.
const MaxRecordPlaintext = 65535

var buckets = []int{256, 1024, 4096, 16384, 65536}

// ErrTooLarge is returned for a record plaintext that needs a blob.
var ErrTooLarge = errors.New("kauri: record plaintext is larger than 65535 bytes")

// Seal is seal(key, plaintext, aad) = nonce(24) || ciphertext || tag (§2).
func Seal(key [32]byte, plaintext, aad []byte) []byte {
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	return SealWithNonce(key, nonce, plaintext, aad)
}

// SealWithNonce is Seal with a given nonce, for test vectors only.
func SealWithNonce(key [32]byte, nonce [24]byte, plaintext, aad []byte) []byte {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	return aead.Seal(append([]byte{}, nonce[:]...), nonce[:], plaintext, aad)
}

// Open reverses Seal.
func Open(key [32]byte, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, errors.New("kauri: ciphertext too short")
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, sealed[:24], sealed[24:], aad)
}

// Pad pads a record plaintext to its bucket (§4.3).
func Pad(p []byte) ([]byte, error) {
	for _, b := range buckets {
		if len(p)+1 <= b {
			return padTo(p, b), nil
		}
	}
	return nil, ErrTooLarge
}

// Pad64 pads blob content to a multiple of 65536 bytes (§4.4).
func Pad64(p []byte) []byte {
	n := (len(p)/65536 + 1) * 65536
	return padTo(p, n)
}

func padTo(p []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, p)
	out[len(p)] = 0x80
	return out
}

// Unpad removes ISO/IEC 7816-4 padding.
func Unpad(p []byte) ([]byte, error) {
	for i := len(p) - 1; i >= 0; i-- {
		switch p[i] {
		case 0:
			continue
		case 0x80:
			return p[:i], nil
		default:
			return nil, errors.New("kauri: bad padding")
		}
	}
	return nil, errors.New("kauri: bad padding")
}

// RecordID is the record ID of a local item (§4.1).
func (c *Chain) RecordID(kind, localUUID string) []byte {
	m := hmac.New(sha256.New, c.IDKey[:])
	m.Write([]byte(kind + ":" + localUUID))
	return m.Sum(nil)[:16]
}

// BlobID is the ID of a blob's plaintext (§4.1).
func (c *Chain) BlobID(content []byte) []byte {
	sum := sha256.Sum256(content)
	m := hmac.New(sha256.New, c.IDKey[:])
	m.Write([]byte("blob:"))
	m.Write(sum[:])
	return m.Sum(nil)[:16]
}

// RecordAAD is the AAD of a record body.
func (c *Chain) RecordAAD(recordID []byte, epoch uint32) []byte {
	return cat(c.ID[:], recordID, u32(epoch))
}

// SealRecord encrypts a record's JSON plaintext.
func (c *Chain) SealRecord(dk [32]byte, epoch uint32, recordID, plaintext []byte) ([]byte, error) {
	padded, err := Pad(plaintext)
	if err != nil {
		return nil, err
	}
	return Seal(dk, padded, c.RecordAAD(recordID, epoch)), nil
}

// OpenRecord decrypts a record body.
func (c *Chain) OpenRecord(dk [32]byte, epoch uint32, recordID, body []byte) ([]byte, error) {
	p, err := Open(dk, body, c.RecordAAD(recordID, epoch))
	if err != nil {
		return nil, err
	}
	return Unpad(p)
}

// SealBlob encrypts blob content.
func (c *Chain) SealBlob(dk [32]byte, epoch uint32, blobID, content []byte) []byte {
	return Seal(dk, Pad64(content), cat(c.ID[:], blobID, u32(epoch)))
}

// OpenBlob decrypts a blob.
func (c *Chain) OpenBlob(dk [32]byte, epoch uint32, blobID, blob []byte) ([]byte, error) {
	p, err := Open(dk, blob, cat(c.ID[:], blobID, u32(epoch)))
	if err != nil {
		return nil, err
	}
	return Unpad(p)
}

// WrapDataKey is the keyring's wrapped data key (§3.2).
func (c *Chain) WrapDataKey(dk [32]byte, epoch uint32) []byte {
	return Seal(c.WrapKey, dk[:], c.keyringAAD(epoch))
}

// UnwrapDataKey reverses WrapDataKey.
func (c *Chain) UnwrapDataKey(wrapped []byte, epoch uint32) ([32]byte, error) {
	var dk [32]byte
	p, err := Open(c.WrapKey, wrapped, c.keyringAAD(epoch))
	if err != nil {
		return dk, err
	}
	if len(p) != 32 {
		return dk, errors.New("kauri: bad data key")
	}
	copy(dk[:], p)
	return dk, nil
}

func (c *Chain) keyringAAD(epoch uint32) []byte {
	return cat([]byte("kauri-sync/v1/keyring"), c.ID[:], u32(epoch))
}

// SealName encrypts a device name.
func (c *Chain) SealName(deviceID []byte, name string) []byte {
	return Seal(c.NameKey, []byte(name), cat([]byte("kauri-sync/v1/name"), deviceID))
}

// OpenName decrypts a device name.
func (c *Chain) OpenName(deviceID, sealed []byte) (string, error) {
	p, err := Open(c.NameKey, sealed, cat([]byte("kauri-sync/v1/name"), deviceID))
	return string(p), err
}

// NewDataKey makes a random data key.
func NewDataKey() [32]byte {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return k
}

// NewChainSecret makes a random chain secret.
func NewChainSecret() [32]byte { return NewDataKey() }
