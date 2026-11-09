package kauri

import (
	"bytes"
	"strings"
	"testing"
)

func TestBIP39KnownVector(t *testing.T) {
	// BIP-39 reference vector: 32 zero bytes.
	m, err := EntropyToMnemonic(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("abandon ", 23) + "art"
	if m != want {
		t.Fatalf("got %q", m)
	}
	// 0x7f repeated: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
	e := bytes.Repeat([]byte{0x7f}, 32)
	m, _ = EntropyToMnemonic(e)
	if !strings.HasSuffix(m, "worth title") || !strings.HasPrefix(m, "legal winner thank year") {
		t.Fatalf("got %q", m)
	}
	back, err := MnemonicToEntropy(m)
	if err != nil || !bytes.Equal(back, e) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := MnemonicToEntropy(strings.Replace(m, "title", "zoo", 1)); err == nil {
		t.Fatal("checksum not checked")
	}
}

func TestRecordRoundTrip(t *testing.T) {
	c := DeriveChain(NewChainSecret())
	dk := NewDataKey()
	id := c.RecordID("snippet", "0b6f7c1e-3e57-4e1e-9a0c-6f3a5d8f1e22")
	if len(id) != 16 {
		t.Fatal("id length")
	}
	plain := []byte(`{"k":"snippet","f":{},"d":null}`)
	body, err := c.SealRecord(dk, 1, id, plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 24+256+16 {
		t.Fatalf("padded size %d", len(body))
	}
	got, err := c.OpenRecord(dk, 1, id, body)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v", err)
	}
	if _, err := c.OpenRecord(dk, 2, id, body); err == nil {
		t.Fatal("epoch is not bound")
	}
	other := c.RecordID("snippet", "another")
	if _, err := c.OpenRecord(dk, 1, other, body); err == nil {
		t.Fatal("record id is not bound")
	}
	if _, err := Pad(make([]byte, 65535)); err != nil {
		t.Fatal("65535 must fit")
	}
	if _, err := Pad(make([]byte, 65536)); err == nil {
		t.Fatal("65536 must not fit")
	}
}

func TestWrapAndName(t *testing.T) {
	c, err := ChainFromWords(DeriveChain(NewChainSecret()).Words())
	if err != nil {
		t.Fatal(err)
	}
	dk := NewDataKey()
	w := c.WrapDataKey(dk, 3)
	got, err := c.UnwrapDataKey(w, 3)
	if err != nil || got != dk {
		t.Fatal("unwrap")
	}
	d := NewDevice()
	n := c.SealName(d.ID(), "Ivan's MacBook")
	if s, err := c.OpenName(d.ID(), n); err != nil || s != "Ivan's MacBook" {
		t.Fatal("name")
	}
}

func TestEnvelopes(t *testing.T) {
	c := DeriveChain(NewChainSecret())
	payload := bytes.Repeat([]byte{7}, 32)
	d := NewDevice()
	env, err := SealEnvelope(c.ID[:], 1, d.Recipient(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if env[0] != envelopeHybrid {
		t.Fatal("expected hybrid")
	}
	got, err := d.OpenEnvelope(c.ID[:], 1, env)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("open: %v", err)
	}
	if _, err := d.OpenEnvelope(c.ID[:], 2, env); err == nil {
		t.Fatal("epoch not bound")
	}
	// X25519-only device.
	old := NewDevice()
	old.MLKEM = nil
	env, _ = SealEnvelope(c.ID[:], 1, old.Recipient(), payload)
	if env[0] != envelopeX25519 {
		t.Fatal("expected x25519 only")
	}
	if got, err := old.OpenEnvelope(c.ID[:], 1, env); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("open x25519")
	}
	if _, err := NewDevice().OpenEnvelope(c.ID[:], 1, env); err == nil {
		t.Fatal("another device opened it")
	}
}

func TestRequestSignature(t *testing.T) {
	d := NewDevice()
	nonce := make([]byte, 16)
	sig := d.SignRequest("POST", "/v1/records", 1762600000, nonce, []byte(`{}`))
	if !VerifyRequest(d.Public(), "POST", "/v1/records", 1762600000, nonce, []byte(`{}`), sig) {
		t.Fatal("verify")
	}
	if VerifyRequest(d.Public(), "POST", "/v1/records", 1762600001, nonce, []byte(`{}`), sig) {
		t.Fatal("time not bound")
	}
	nonce[0] = 1
	if VerifyRequest(d.Public(), "POST", "/v1/records", 1762600000, nonce, []byte(`{}`), sig) {
		t.Fatal("nonce not bound")
	}
}

func TestPairing(t *testing.T) {
	code, err := NormalizePairCode(NewPairCode())
	if err != nil {
		t.Fatal(err)
	}
	a := NewPairing(code, true)
	b := NewPairing(code, false)
	if a.Slot != b.Slot {
		t.Fatal("slots differ")
	}
	kb, err := b.Finish(a.Msg)
	if err != nil {
		t.Fatal(err)
	}
	ka, err := a.Finish(b.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ka.CheckConfirm(kb.ConfirmB) || ka.BoxKey != kb.BoxKey || ka.Number != kb.Number {
		t.Fatal("the two sides disagree")
	}
	secret := NewChainSecret()
	box := ka.SealApproval(a.Slot, secret)
	if got, err := kb.OpenApproval(b.Slot, box); err != nil || got != secret {
		t.Fatal("approval")
	}

	// A wrong secret part fails the confirmation.
	wrong := code[:4] + strings.Repeat("0", 8)
	if wrong == code {
		wrong = code[:4] + strings.Repeat("1", 8)
	}
	bad := NewPairing(wrong, false)
	kbad, err := bad.Finish(a.Msg)
	if err != nil {
		t.Fatal(err)
	}
	ka2, _ := a.Finish(bad.Msg)
	if ka2.CheckConfirm(kbad.ConfirmB) {
		t.Fatal("a wrong code was accepted")
	}

	// Small-order and garbage points are rejected.
	identity := make([]byte, 32)
	identity[0] = 1
	if _, err := a.Finish(identity); err == nil {
		t.Fatal("identity accepted")
	}
}

func TestNormalizePairCode(t *testing.T) {
	got, err := NormalizePairCode("abcd-efgh-ojkl")
	if err != nil || got != "ABCDEFGH0JK1" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := NormalizePairCode("ABCD-EFGH-JKU0"); err == nil {
		t.Fatal("U accepted")
	}
}
