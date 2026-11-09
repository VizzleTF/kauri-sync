package kauri

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strconv"
)

// Header names of a signed request (§7.1).
const (
	HeaderProtocol  = "Kauri-Protocol"
	HeaderChain     = "Kauri-Chain"
	HeaderDevice    = "Kauri-Device"
	HeaderTime      = "Kauri-Time"
	HeaderNonce     = "Kauri-Nonce"
	HeaderSignature = "Kauri-Signature"
)

// RequestMessage is what a device signs for a request. path includes the
// query string, if any; nonce is the 16 random bytes of Kauri-Nonce, which
// keep two identical requests in the same second from sharing a signature.
func RequestMessage(method, path string, unix int64, nonce, body []byte) []byte {
	sum := sha256.Sum256(body)
	m := []byte("kauri-sync/v1/request\x00")
	m = append(m, method...)
	m = append(m, 0)
	m = append(m, path...)
	m = append(m, 0)
	m = strconv.AppendInt(m, unix, 10)
	m = append(m, 0)
	m = append(m, nonce...)
	return append(m, sum[:]...)
}

// SignRequest signs a request with the device key.
func (d *Device) SignRequest(method, path string, unix int64, nonce, body []byte) []byte {
	return ed25519.Sign(d.Sign, RequestMessage(method, path, unix, nonce, body))
}

// VerifyRequest checks a request signature.
func VerifyRequest(pub ed25519.PublicKey, method, path string, unix int64, nonce, body, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(nonce) == 16 &&
		ed25519.Verify(pub, RequestMessage(method, path, unix, nonce, body), sig)
}
