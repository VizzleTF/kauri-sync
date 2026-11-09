package kauri

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strconv"
)

// Device is a device's three key pairs (§3.3).
type Device struct {
	Sign   ed25519.PrivateKey
	X25519 *ecdh.PrivateKey
	// MLKEM is nil for a device without ML-KEM.
	MLKEM *mlkem.DecapsulationKey768
}

// DeviceFromSeeds rebuilds a device from its private key seeds: 32 bytes of
// Ed25519 seed, 32 bytes of X25519 private key and, optionally, 64 bytes of
// ML-KEM-768 seed (d || z).
func DeviceFromSeeds(sign, x25519, mlkemSeed []byte) (*Device, error) {
	if len(sign) != ed25519.SeedSize {
		return nil, errors.New("kauri: Ed25519 seed must be 32 bytes")
	}
	x, err := ecdh.X25519().NewPrivateKey(x25519)
	if err != nil {
		return nil, err
	}
	d := &Device{Sign: ed25519.NewKeyFromSeed(sign), X25519: x}
	if len(mlkemSeed) > 0 {
		if d.MLKEM, err = mlkem.NewDecapsulationKey768(mlkemSeed); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// NewDevice makes a device with all three keys.
func NewDevice() *Device {
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	k, _ := mlkem.GenerateKey768()
	return &Device{Sign: sign, X25519: x, MLKEM: k}
}

// Public is the device's public key.
func (d *Device) Public() ed25519.PublicKey { return d.Sign.Public().(ed25519.PublicKey) }

// ID is the device ID.
func (d *Device) ID() []byte { return DeviceID(d.Public()) }

// Recipient is what is needed to seal an envelope to a device.
type Recipient struct {
	ID     []byte
	X25519 []byte
	MLKEM  []byte // empty: X25519 only
}

// Recipient returns this device as an envelope recipient.
func (d *Device) Recipient() Recipient {
	r := Recipient{ID: d.ID(), X25519: d.X25519.PublicKey().Bytes()}
	if d.MLKEM != nil {
		r.MLKEM = d.MLKEM.EncapsulationKey().Bytes()
	}
	return r
}

const (
	envelopeX25519 = 0x01
	envelopeHybrid = 0x02
)

// SealEnvelope seals a 32-byte payload to a device (§3.3).
func SealEnvelope(chainID []byte, epoch uint32, to Recipient, payload []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return sealEnvelope(chainID, epoch, to, payload, eph)
}

func sealEnvelope(chainID []byte, epoch uint32, to Recipient, payload []byte, eph *ecdh.PrivateKey) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(to.X25519)
	if err != nil {
		return nil, err
	}
	ssx, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(ssx, make([]byte, 32)) == 1 {
		return nil, errors.New("kauri: X25519 result is all zeros")
	}
	E := eph.PublicKey().Bytes()
	var ctk, ssk []byte
	kind := byte(envelopeX25519)
	if len(to.MLKEM) > 0 {
		ek, err := mlkem.NewEncapsulationKey768(to.MLKEM)
		if err != nil {
			return nil, err
		}
		ssk, ctk = ek.Encapsulate()
		kind = envelopeHybrid
	}
	k, err := envelopeKey(ssx, ssk, E, ctk, to.X25519, to.ID)
	if err != nil {
		return nil, err
	}
	aad := cat(chainID, u32(epoch), to.ID)
	return cat([]byte{kind}, E, ctk, Seal(k, payload, aad)), nil
}

// OpenEnvelope opens an envelope sealed to d.
func (d *Device) OpenEnvelope(chainID []byte, epoch uint32, env []byte) ([]byte, error) {
	if len(env) < 1+32 {
		return nil, errors.New("kauri: envelope too short")
	}
	kind, rest := env[0], env[1:]
	E, rest := rest[:32], rest[32:]
	var ctk, ssk []byte
	switch kind {
	case envelopeX25519:
	case envelopeHybrid:
		if d.MLKEM == nil || len(rest) < mlkem.CiphertextSize768 {
			return nil, errors.New("kauri: cannot open a hybrid envelope")
		}
		ctk, rest = rest[:mlkem.CiphertextSize768], rest[mlkem.CiphertextSize768:]
		var err error
		if ssk, err = d.MLKEM.Decapsulate(ctk); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("kauri: unknown envelope type " + strconv.Itoa(int(kind)))
	}
	pub, err := ecdh.X25519().NewPublicKey(E)
	if err != nil {
		return nil, err
	}
	ssx, err := d.X25519.ECDH(pub)
	if err != nil {
		return nil, err
	}
	k, err := envelopeKey(ssx, ssk, E, ctk, d.X25519.PublicKey().Bytes(), d.ID())
	if err != nil {
		return nil, err
	}
	return Open(k, rest, cat(chainID, u32(epoch), d.ID()))
}

func envelopeKey(ssx, ssk, E, ctk, recipientX, deviceID []byte) ([32]byte, error) {
	var k [32]byte
	b, err := hkdf.Key(sha256.New, cat(ssx, ssk), []byte("kauri-sync/v1/envelope"), string(cat(E, ctk, recipientX, deviceID)), 32)
	if err != nil {
		return k, err
	}
	copy(k[:], b)
	return k, nil
}
