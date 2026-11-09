package kauri

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"filippo.io/edwards25519"
)

// Pairing (§8): SPAKE2 (RFC 9382) over edwards25519.

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var (
	pointM = mustPoint("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
	pointN = mustPoint("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")
	eight  = func() *edwards25519.Scalar {
		var b [32]byte
		b[0] = 8
		s, _ := edwards25519.NewScalar().SetCanonicalBytes(b[:])
		return s
	}()
)

func mustPoint(h string) *edwards25519.Point {
	b, _ := hex.DecodeString(h)
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		panic(err)
	}
	return p
}

// NewPairCode makes a 12-character pairing code, formatted XXXX-XXXX-XXXX.
func NewPairCode() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	var sb strings.Builder
	for i, c := range b {
		if i == 4 || i == 8 {
			sb.WriteByte('-')
		}
		sb.WriteByte(crockford[c&31])
	}
	return sb.String()
}

// NormalizePairCode upper-cases a typed code, maps O to 0 and I, L to 1, and
// drops separators. It returns the 12 characters or an error.
func NormalizePairCode(code string) (string, error) {
	var sb strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch r {
		case '-', ' ':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(crockford, r) {
			return "", errors.New("kauri: the pairing code has a character that cannot be in it")
		}
		sb.WriteRune(r)
	}
	if sb.Len() != 12 {
		return "", errors.New("kauri: a pairing code has 12 characters")
	}
	return sb.String(), nil
}

// PairSlot is the slot ID of a normalized code.
func PairSlot(code string) string {
	sum := sha256.Sum256([]byte("kauri-pair-slot-v1\x00" + code[:4]))
	return hex.EncodeToString(sum[:])
}

func pairW(slot, code string) *edwards25519.Scalar {
	h := sha512.Sum512([]byte("kauri-pair-v1\x00" + slot + "\x00" + code[4:]))
	w, _ := edwards25519.NewScalar().SetUniformBytes(h[:])
	return w
}

// Pairing is one side of a SPAKE2 exchange.
type Pairing struct {
	Slot     string
	existing bool
	w, x     *edwards25519.Scalar
	Msg      []byte // our SPAKE2 message
}

// NewPairing starts SPAKE2 for a normalized code. existing is true on the
// device that is already in the chain (A).
func NewPairing(code string, existing bool) *Pairing {
	var r [64]byte
	_, _ = rand.Read(r[:])
	x, _ := edwards25519.NewScalar().SetUniformBytes(r[:])
	return newPairing(code, existing, x)
}

func newPairing(code string, existing bool, x *edwards25519.Scalar) *Pairing {
	slot := PairSlot(code)
	p := &Pairing{Slot: slot, existing: existing, w: pairW(slot, code), x: x}
	mask := pointN
	if existing {
		mask = pointM
	}
	X := new(edwards25519.Point).ScalarBaseMult(x)
	p.Msg = new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(p.w, mask), X).Bytes()
	return p
}

// PairKeys are the results of SPAKE2.
type PairKeys struct {
	// ConfirmB is cB, sent by the new device and checked by the existing one.
	ConfirmB []byte
	BoxKey   [32]byte
	// Number is shown on both screens.
	Number int
}

// Finish completes SPAKE2 with the other side's message.
func (p *Pairing) Finish(peer []byte) (*PairKeys, error) {
	P, err := new(edwards25519.Point).SetBytes(peer)
	if err != nil {
		return nil, errors.New("kauri: bad pairing message")
	}
	// Prime-order subgroup check: L·P must be the identity.
	if new(edwards25519.Point).MultByCofactor(P).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, errors.New("kauri: bad pairing message")
	}
	if !inPrimeSubgroup(P) {
		return nil, errors.New("kauri: bad pairing message")
	}
	peerMask := pointM
	if p.existing {
		peerMask = pointN
	}
	T := new(edwards25519.Point).Subtract(P, new(edwards25519.Point).ScalarMult(p.w, peerMask))
	K := new(edwards25519.Point).ScalarMult(edwards25519.NewScalar().Multiply(eight, p.x), T)
	var pA, pB []byte
	if p.existing {
		pA, pB = p.Msg, peer
	} else {
		pA, pB = peer, p.Msg
	}
	tt := transcript(pA, pB, K.Bytes(), p.w)
	h := sha256.Sum256(tt)
	ke, ka := h[:16], h[16:]
	kc, err := hkdf.Key(sha256.New, ka, nil, "ConfirmationKeys"+p.Slot, 32)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, kc[16:])
	mac.Write(tt)
	keys := &PairKeys{ConfirmB: mac.Sum(nil)}
	box, _ := hkdf.Key(sha256.New, ke, []byte("kauri-pair-v1"), "box", 32)
	copy(keys.BoxKey[:], box)
	v, _ := hkdf.Key(sha256.New, ke, []byte("kauri-pair-v1"), "verify", 4)
	keys.Number = int(binary.BigEndian.Uint32(v) % 10000)
	return keys, nil
}

// inPrimeSubgroup reports whether L·P is the identity.
func inPrimeSubgroup(P *edwards25519.Point) bool {
	// L = 2^252 + 27742317777372353535851937790883648493; L·P = 0 ⇔ P in the
	// prime-order subgroup. Compute it as (L-1)·P + P.
	lMinus1, _ := edwards25519.NewScalar().SetCanonicalBytes(lMinusOne[:])
	q := new(edwards25519.Point).ScalarMult(lMinus1, P)
	return q.Add(q, P).Equal(edwards25519.NewIdentityPoint()) == 1
}

// L - 1 in little-endian.
var lMinusOne = [32]byte{
	0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
}

// CheckConfirm checks cB in constant time.
func (k *PairKeys) CheckConfirm(cB []byte) bool { return hmac.Equal(k.ConfirmB, cB) }

func transcript(pA, pB, K []byte, w *edwards25519.Scalar) []byte {
	// w as a 32-byte big-endian number.
	le := w.Bytes()
	be := make([]byte, 32)
	for i := range le {
		be[31-i] = le[i]
	}
	var tt []byte
	for _, part := range [][]byte{[]byte("kauri-pair-existing"), []byte("kauri-pair-new"), pA, pB, K, be} {
		tt = binary.LittleEndian.AppendUint64(tt, uint64(len(part)))
		tt = append(tt, part...)
	}
	return tt
}

// SealJoin seals the new device's info for the existing device.
func (k *PairKeys) SealJoin(slot string, deviceInfo []byte) []byte {
	return Seal(k.BoxKey, deviceInfo, []byte("kauri-pair-v1/join"+slot))
}

// OpenJoin opens it.
func (k *PairKeys) OpenJoin(slot string, box []byte) ([]byte, error) {
	return Open(k.BoxKey, box, []byte("kauri-pair-v1/join"+slot))
}

// SealApproval seals the chain secret for the new device.
func (k *PairKeys) SealApproval(slot string, secret [32]byte) []byte {
	return Seal(k.BoxKey, secret[:], []byte("kauri-pair-v1/approve"+slot))
}

// OpenApproval opens it.
func (k *PairKeys) OpenApproval(slot string, box []byte) ([32]byte, error) {
	var s [32]byte
	p, err := Open(k.BoxKey, box, []byte("kauri-pair-v1/approve"+slot))
	if err != nil {
		return s, err
	}
	if len(p) != 32 {
		return s, errors.New("kauri: bad approval")
	}
	copy(s[:], p)
	return s, nil
}

// NewPairingFromSeed is NewPairing with the secret scalar derived from 64
// bytes of seed, for test vectors only.
func NewPairingFromSeed(code string, existing bool, seed []byte) *Pairing {
	x, err := edwards25519.NewScalar().SetUniformBytes(seed)
	if err != nil {
		panic(err)
	}
	return newPairing(code, existing, x)
}
