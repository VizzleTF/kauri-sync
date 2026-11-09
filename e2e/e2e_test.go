//go:build integration

// End-to-end tests: the real server on a real Postgres, driven by the
// reference client in package kauri.
package e2e

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/VizzleTF/kauri-sync/internal/api"
	"github.com/VizzleTF/kauri-sync/internal/events"
	"github.com/VizzleTF/kauri-sync/internal/store"
	"github.com/VizzleTF/kauri-sync/internal/testpg"
	"github.com/VizzleTF/kauri-sync/kauri"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	p, stop, err := testpg.Start(ctx)
	if err != nil {
		panic(err)
	}
	pool = p
	code := m.Run()
	stop()
	os.Exit(code)
}

type env struct {
	srv *httptest.Server
	st  *store.Store
	api *api.API
}

func newEnv(t *testing.T, tweak func(*api.Config)) *env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st := store.New(pool)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	hub := events.New(pool, log, 20)
	go hub.Listen(ctx)
	cfg := api.Config{Store: st, Hub: hub, Log: log, MaxBytesPerChain: 256 << 20, MaxRecords: 100000}
	if tweak != nil {
		tweak(&cfg)
	}
	a := api.New(cfg)
	mux := http.NewServeMux()
	mux.Handle("/v1/", a.Routes())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	time.Sleep(50 * time.Millisecond) // let LISTEN start
	return &env{srv: srv, st: st, api: a}
}

func (e *env) client(chain *kauri.Chain) *kauri.Client {
	return &kauri.Client{Server: e.srv.URL, Chain: chain, Device: kauri.NewDevice()}
}

func snippet(t *testing.T, c *kauri.Client, dk [32]byte, epoch uint32, uuid, title string) kauri.RecordIn {
	t.Helper()
	plain, _ := json.Marshal(map[string]any{
		"k": "snippet",
		"f": map[string]any{"title": []any{title, []any{time.Now().UnixMilli(), 0, kauri.B64.EncodeToString(c.Device.ID())}}},
		"d": nil,
	})
	id := c.Chain.RecordID("snippet", uuid)
	body, err := c.Chain.SealRecord(dk, epoch, id, plain)
	if err != nil {
		t.Fatal(err)
	}
	return kauri.RecordIn{ID: id, Epoch: epoch, Body: body}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	if got := kauri.StatusOf(err); got != status {
		t.Fatalf("want %d, got %v", status, err)
	}
}

func TestSyncBetweenTwoDevices(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	chain := kauri.DeriveChain(kauri.NewChainSecret())
	a := e.client(chain)
	dkA, err := a.CreateChain(ctx, "Windows PC")
	must(t, err)
	wantStatus(t, func() error { _, err := a.CreateChain(ctx, "again"); return err }(), http.StatusConflict)

	// B joins from the 24 words and recovers the data key from the wrapped copy.
	chainB, err := kauri.ChainFromWords(chain.Words())
	must(t, err)
	b := e.client(chainB)
	must(t, b.JoinWithCode(ctx, "MacBook"))
	epoch, dkB, err := b.DataKey(ctx)
	must(t, err)
	if dkB != dkA || epoch != 1 {
		t.Fatal("B got another data key")
	}

	evCtx, stop := context.WithCancel(ctx)
	defer stop()
	evs, err := b.Events(evCtx)
	must(t, err)
	if ev := <-evs; ev.Kind != "ready" {
		t.Fatalf("first event %q", ev.Kind)
	}

	rec := snippet(t, a, dkA, 1, "6d2f3c50-0000-4000-8000-000000000001", "Hello")
	vs, err := a.WriteRecords(ctx, []kauri.RecordIn{rec})
	must(t, err)
	select {
	case ev := <-evs:
		if ev.Kind != "changed" {
			t.Fatalf("event %q", ev.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no changed event")
	}

	ch, err := b.Changes(ctx, 0, 100)
	must(t, err)
	if len(ch.Records) != 1 || ch.Version != vs[0] {
		t.Fatalf("changes %+v", ch)
	}
	id, _ := kauri.B64.DecodeString(ch.Records[0].ID)
	body, _ := kauri.B64.DecodeString(ch.Records[0].Body)
	plain, err := chainB.OpenRecord(dkB, ch.Records[0].Epoch, id, body)
	must(t, err)
	var doc map[string]any
	must(t, json.Unmarshal(plain, &doc))
	if doc["k"] != "snippet" {
		t.Fatal("wrong plaintext")
	}

	// Optimistic concurrency.
	stale := int64(0)
	rec2 := snippet(t, b, dkB, 1, "6d2f3c50-0000-4000-8000-000000000001", "Hello!")
	rec2.IfVersion = &stale
	_, err = b.WriteRecords(ctx, []kauri.RecordIn{rec2})
	wantStatus(t, err, http.StatusConflict)
	rec2.IfVersion = &vs[0]
	_, err = b.WriteRecords(ctx, []kauri.RecordIn{rec2})
	must(t, err)

	// A device that is not in the chain is refused.
	outsider := e.client(chain)
	_, err = outsider.Changes(ctx, 0, 10)
	wantStatus(t, err, http.StatusUnauthorized)
}

func TestReplayAndClock(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	a := e.client(kauri.DeriveChain(kauri.NewChainSecret()))
	_, err := a.CreateChain(ctx, "A")
	must(t, err)
	fixed := time.Now()
	a.Now = func() time.Time { return fixed }
	a.Nonce = []byte("0123456789abcdef")
	_, err = a.Changes(ctx, 0, 10)
	must(t, err)
	_, err = a.Changes(ctx, 0, 10) // the same signature again
	wantStatus(t, err, http.StatusUnauthorized)
	a.Now = func() time.Time { return time.Now().Add(-10 * time.Minute) }
	_, err = a.Changes(ctx, 0, 11)
	wantStatus(t, err, http.StatusUnauthorized)
}

func TestRemoveDevice(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	chain := kauri.DeriveChain(kauri.NewChainSecret())
	a := e.client(chain)
	_, err := a.CreateChain(ctx, "A")
	must(t, err)
	b := e.client(chain)
	must(t, b.JoinWithCode(ctx, "B"))
	evs, err := b.Events(ctx)
	must(t, err)
	<-evs
	must(t, a.Do(ctx, "DELETE", "/v1/devices/"+kauri.B64.EncodeToString(b.Device.ID()), nil, nil))
	select {
	case ev := <-evs:
		if ev.Kind != "removed" {
			t.Fatalf("event %q", ev.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no removed event")
	}
	_, err = b.Changes(ctx, 0, 10)
	wantStatus(t, err, http.StatusForbidden)
	// It cannot rejoin with the sync code under the same key.
	wantStatus(t, b.JoinWithCode(ctx, "B"), http.StatusForbidden)
}

func TestPairing(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	chain := kauri.DeriveChain(kauri.NewChainSecret())
	a := e.client(chain)
	dk, err := a.CreateChain(ctx, "A")
	must(t, err)

	code, _ := kauri.NormalizePairCode(kauri.NewPairCode())
	pa := kauri.NewPairing(code, true)
	must(t, a.PairOpen(ctx, pa))

	// The new device: no chain yet, only the code the user typed.
	newDev := kauri.NewDevice()
	pb := kauri.NewPairing(code, false)
	slot, err := kauri.PairGet(ctx, e.srv.URL, pb.Slot)
	must(t, err)
	amsg, _ := kauri.B64.DecodeString(slot.Msg)
	kb, err := pb.Finish(amsg)
	must(t, err)
	// B does not know the chain yet, so it cannot seal its name with name_key;
	// it sends the plain name inside the box and A seals it.
	r := newDev.Recipient()
	info, _ := json.Marshal(map[string]string{
		"sign": kauri.B64.EncodeToString(newDev.Public()), "x25519": kauri.B64.EncodeToString(r.X25519),
		"mlkem": kauri.B64.EncodeToString(r.MLKEM), "name": "New laptop",
	})
	must(t, kauri.PairJoin(ctx, e.srv.URL, pb.Slot, pb.Msg, kb.ConfirmB, kb.SealJoin(pb.Slot, info)))
	wantStatus(t, kauri.PairJoin(ctx, e.srv.URL, pb.Slot, pb.Msg, kb.ConfirmB, kb.SealJoin(pb.Slot, info)), http.StatusConflict)

	// A checks the confirmation, opens B's info, adds it and approves.
	st, err := kauri.PairGet(ctx, e.srv.URL, pa.Slot)
	must(t, err)
	bmsg, _ := kauri.B64.DecodeString(st.BMsg)
	ka, err := pa.Finish(bmsg)
	must(t, err)
	confirm, _ := kauri.B64.DecodeString(st.Confirm)
	if !ka.CheckConfirm(confirm) || ka.Number != kb.Number {
		t.Fatal("confirmation failed")
	}
	box, _ := kauri.B64.DecodeString(st.Box)
	raw, err := ka.OpenJoin(pa.Slot, box)
	must(t, err)
	var got map[string]string
	must(t, json.Unmarshal(raw, &got))
	sign, _ := kauri.B64.DecodeString(got["sign"])
	got["name"] = kauri.B64.EncodeToString(chain.SealName(kauri.DeviceID(sign), got["name"]))
	must(t, a.AddDevice(ctx, got, 1, dk))
	must(t, a.PairApprove(ctx, pa.Slot, ka.SealApproval(pa.Slot, chain.Secret)))

	// B opens the approval and is a member with an envelope.
	st, err = kauri.PairGet(ctx, e.srv.URL, pb.Slot)
	must(t, err)
	approval, _ := kauri.B64.DecodeString(st.Approval)
	secret, err := kb.OpenApproval(pb.Slot, approval)
	must(t, err)
	b := &kauri.Client{Server: e.srv.URL, Chain: kauri.DeriveChain(secret), Device: newDev}
	_, dkB, err := b.DataKey(ctx)
	must(t, err)
	if dkB != dk {
		t.Fatal("B got another data key")
	}
}

func TestBlobsLimitsAndForward(t *testing.T) {
	e := newEnv(t, func(c *api.Config) { c.MaxRecords = 2 })
	ctx := context.Background()
	chain := kauri.DeriveChain(kauri.NewChainSecret())
	a := e.client(chain)
	dk, err := a.CreateChain(ctx, "A")
	must(t, err)
	b := e.client(chain)
	must(t, b.JoinWithCode(ctx, "B"))

	content := []byte("image bytes")
	blobID := chain.BlobID(content)
	sealed := chain.SealBlob(dk, 1, blobID, content)
	rec := snippet(t, a, dk, 1, "clip-1", "x")
	rec.Blobs = [][]byte{blobID}
	_, err = a.WriteRecords(ctx, []kauri.RecordIn{rec})
	wantStatus(t, err, http.StatusBadRequest) // the blob is not uploaded yet
	must(t, a.PutBlob(ctx, blobID, sealed))
	_, err = a.WriteRecords(ctx, []kauri.RecordIn{rec})
	must(t, err)
	data, err := b.GetBlob(ctx, blobID)
	must(t, err)
	if plain, err := chain.OpenBlob(dk, 1, blobID, data); err != nil || string(plain) != string(content) {
		t.Fatal("blob round trip")
	}

	// MaxRecords = 2.
	_, err = a.WriteRecords(ctx, []kauri.RecordIn{snippet(t, a, dk, 1, "s2", "y"), snippet(t, a, dk, 1, "s3", "z")})
	wantStatus(t, err, http.StatusRequestEntityTooLarge)

	// Forward the chain to new secrets for B.
	next := kauri.NewChainSecret()
	env, err := kauri.SealEnvelope(chain.ID[:], 0, b.Device.Recipient(), next[:])
	must(t, err)
	body, _ := json.Marshal(map[string]any{"envelopes": []map[string]string{{
		"device": kauri.B64.EncodeToString(b.Device.ID()), "envelope": kauri.B64.EncodeToString(env),
	}}})
	must(t, a.Do(ctx, "POST", "/v1/forward", body, nil))
	_, err = b.Changes(ctx, 0, 10)
	wantStatus(t, err, http.StatusGone)
	var fwd struct {
		Envelope string `json:"envelope"`
	}
	must(t, b.Do(ctx, "GET", "/v1/forward", nil, &fwd))
	raw, _ := kauri.B64.DecodeString(fwd.Envelope)
	got, err := b.Device.OpenEnvelope(chain.ID[:], 0, raw)
	must(t, err)
	if string(got) != string(next[:]) {
		t.Fatal("forward envelope")
	}
}

func TestCleanCompactsTombstones(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	chain := kauri.DeriveChain(kauri.NewChainSecret())
	a := e.client(chain)
	dk, err := a.CreateChain(ctx, "A")
	must(t, err)
	for _, id := range []string{"gone-1", "gone-2"} {
		rec := snippet(t, a, dk, 1, id, "x")
		rec.Deleted = true
		_, err = a.WriteRecords(ctx, []kauri.RecordIn{rec})
		must(t, err)
	}
	_, err = a.WriteRecords(ctx, []kauri.RecordIn{snippet(t, a, dk, 1, "kept", "y")})
	must(t, err)
	_, err = e.st.Clean(ctx, store.Retention{Tombstones: -time.Hour, BlobGrace: time.Hour, Forwards: time.Hour, PairSlots: time.Hour})
	must(t, err)
	_, err = a.Changes(ctx, 1, 10)
	wantStatus(t, err, http.StatusGone) // resync
	ch, err := a.Changes(ctx, 0, 10)
	must(t, err)
	if len(ch.Records) != 1 {
		t.Fatalf("want only the live record, got %d", len(ch.Records))
	}
}
