// Package kauri is the reference implementation of the client side of Kauri
// Sync v1 (docs/sync.md in github.com/VizzleTF/kauri): key derivation from
// the sync code, record and blob encryption, envelopes, request signatures
// and pairing. The Windows and macOS clients are checked against test
// vectors generated from it.
package kauri

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// Protocol is the protocol version this package implements.
const Protocol = 1

const salt = "kauri-sync/v1"

// B64 is the encoding of bytes in the protocol: base64url without padding.
var B64 = base64.RawURLEncoding

// Chain holds the values derived from a chain secret (§3.1).
type Chain struct {
	Secret  [32]byte
	ID      [32]byte
	AuthKey ed25519.PrivateKey
	WrapKey [32]byte
	IDKey   [32]byte
	NameKey [32]byte
}

// DeriveChain derives the chain values from the 32-byte chain secret.
func DeriveChain(secret [32]byte) *Chain {
	c := &Chain{Secret: secret}
	c.ID = derive32(secret[:], "chain-id")
	seed := derive32(secret[:], "chain-auth")
	c.AuthKey = ed25519.NewKeyFromSeed(seed[:])
	c.WrapKey = derive32(secret[:], "wrap-key")
	c.IDKey = derive32(secret[:], "record-id-key")
	c.NameKey = derive32(secret[:], "device-name-key")
	return c
}

// ChainFromWords derives the chain from a 24-word sync code.
func ChainFromWords(words string) (*Chain, error) {
	entropy, err := MnemonicToEntropy(words)
	if err != nil {
		return nil, err
	}
	if len(entropy) != 32 {
		return nil, fmt.Errorf("kauri: a sync code has 24 words")
	}
	var s [32]byte
	copy(s[:], entropy)
	return DeriveChain(s), nil
}

// Words returns the chain's sync code.
func (c *Chain) Words() string {
	m, _ := EntropyToMnemonic(c.Secret[:])
	return m
}

// AuthPublic is the chain key's public key.
func (c *Chain) AuthPublic() ed25519.PublicKey { return c.AuthKey.Public().(ed25519.PublicKey) }

// AddSignature is chain_sig for adding a device (§7.2).
func (c *Chain) AddSignature(devicePub ed25519.PublicKey) []byte {
	return ed25519.Sign(c.AuthKey, AddMessage(c.ID[:], devicePub))
}

// AddMessage is what chain_sig signs.
func AddMessage(chainID []byte, devicePub ed25519.PublicKey) []byte {
	m := []byte("kauri-sync/v1/add\x00")
	m = append(m, chainID...)
	return append(m, devicePub...)
}

// IDHash is what the server stores for a chain: SHA-256(chain_id).
func IDHash(chainID []byte) [32]byte { return sha256.Sum256(chainID) }

// DeviceID is SHA-256(device public key)[0..16].
func DeviceID(devicePub ed25519.PublicKey) []byte {
	h := sha256.Sum256(devicePub)
	return h[:16]
}

func derive32(secret []byte, info string) [32]byte {
	var out [32]byte
	b, err := hkdf.Key(sha256.New, secret, []byte(salt), info, 32)
	if err != nil {
		panic(err)
	}
	copy(out[:], b)
	return out
}

func u32(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }

func cat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
