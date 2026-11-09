// Package api serves Kauri Sync v1 (docs/sync.md §7 and §8).
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/VizzleTF/kauri-sync/internal/clientip"
	"github.com/VizzleTF/kauri-sync/internal/events"
	"github.com/VizzleTF/kauri-sync/internal/ratelimit"
	"github.com/VizzleTF/kauri-sync/internal/store"
	"github.com/VizzleTF/kauri-sync/kauri"
)

// Config is what the API needs.
type Config struct {
	Store *store.Store
	Hub   *events.Hub
	Log   *slog.Logger

	MaxBytesPerChain int64
	MaxRecords       int64
	MaxBlobBytes     int64
	MaxBatchRecords  int
	MaxBatchBytes    int64
	ClockSkew        time.Duration
	PairTTL          time.Duration

	// Rate limits; nil for none.
	ChainCreates *ratelimit.Limiter // per client address
	PairOpens    *ratelimit.Limiter // per chain
	PairJoins    *ratelimit.Limiter // per client address
	PairReads    *ratelimit.Limiter // per client address

	// Now is the clock; tests override it.
	Now func() time.Time
}

// API is the handler.
type API struct{ Config }

// New returns the API with defaults filled in.
func New(c Config) *API {
	if c.ClockSkew == 0 {
		c.ClockSkew = 300 * time.Second
	}
	if c.PairTTL == 0 {
		c.PairTTL = 5 * time.Minute
	}
	if c.MaxBatchRecords == 0 {
		c.MaxBatchRecords = 1000
	}
	if c.MaxBatchBytes == 0 {
		c.MaxBatchBytes = 8 << 20
	}
	if c.MaxBlobBytes == 0 {
		c.MaxBlobBytes = 16 << 20
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &API{c}
}

// Routes returns the /v1 routes.
func (a *API) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/chains", a.signed(modeCreate, a.createChain))
	m.HandleFunc("POST /v1/devices", a.signed(modeJoin, a.addDevice))
	m.HandleFunc("GET /v1/devices", a.signed(modeMember, a.listDevices))
	m.HandleFunc("DELETE /v1/devices/{id}", a.signed(modeMember, a.removeDevice))
	m.HandleFunc("GET /v1/keyring", a.signed(modeMember, a.keyring))
	m.HandleFunc("POST /v1/keyring", a.signed(modeMember, a.newEpoch))
	m.HandleFunc("GET /v1/changes", a.signed(modeMember, a.changes))
	m.HandleFunc("POST /v1/records", a.signed(modeMember, a.writeRecords))
	m.HandleFunc("PUT /v1/blobs/{id}", a.signed(modeMember, a.putBlob))
	m.HandleFunc("GET /v1/blobs/{id}", a.signed(modeMember, a.getBlob))
	m.HandleFunc("GET /v1/events", a.signed(modeMember, a.events))
	m.HandleFunc("POST /v1/forward", a.signed(modeMember, a.forward))
	m.HandleFunc("GET /v1/forward", a.signed(modeForwarded, a.getForward))
	m.HandleFunc("POST /v1/pair", a.signed(modeMember, a.pairOpen))
	m.HandleFunc("GET /v1/pair/{slot}", a.pairGet)
	m.HandleFunc("POST /v1/pair/{slot}/join", a.pairJoin)
	m.HandleFunc("POST /v1/pair/{slot}/approve", a.signed(modeMember, a.pairApprove))
	m.HandleFunc("DELETE /v1/pair/{slot}", a.signed(modeMember, a.pairDelete))
	return m
}

// ---- JSON helpers ----

// Bytes marshal as base64url without padding.
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) { return json.Marshal(kauri.B64.EncodeToString(b)) }

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := kauri.B64.DecodeString(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(max(wait, time.Second)/time.Second)))
	fail(w, http.StatusTooManyRequests, "too many requests; try again later")
}

func allow(w http.ResponseWriter, l *ratelimit.Limiter, key string) bool {
	if l == nil || key == "" {
		return true
	}
	if ok, wait := l.Allow(key); !ok {
		tooMany(w, wait)
		return false
	}
	return true
}

func addrKey(r *http.Request) string { return clientip.Key(clientip.FromContext(r.Context())) }

// ---- signed requests (§7.1) ----

type mode int

const (
	modeMember    mode = iota // a member of a live chain
	modeCreate                // the chain must not exist yet
	modeJoin                  // a live chain; the device may be new
	modeForwarded             // a member; the chain may have moved
)

type caller struct {
	chainID   []byte // raw chain_id from the header
	chain     []byte // SHA-256(chain_id), the stored key
	devicePub ed25519.PublicKey
	deviceID  []byte
	row       store.Chain
	member    bool
	body      []byte
}

func (a *API) bodyLimit(r *http.Request) int64 {
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/blobs/"):
		return a.MaxBlobBytes + 64<<10
	case r.URL.Path == "/v1/records":
		// base64 and JSON overhead on top of the batch limit
		return a.MaxBatchBytes*3/2 + 64<<10
	default:
		return 64 << 10
	}
}

func (a *API) signed(m mode, h func(http.ResponseWriter, *http.Request, *caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.authenticate(w, r, m)
		if ok {
			h(w, r, c)
		}
	}
}

func (a *API) authenticate(w http.ResponseWriter, r *http.Request, m mode) (*caller, bool) {
	unauthorized := func(msg string) (*caller, bool) {
		fail(w, http.StatusUnauthorized, msg)
		return nil, false
	}
	if p := r.Header.Get(kauri.HeaderProtocol); p != "" && p != strconv.Itoa(kauri.Protocol) {
		fail(w, http.StatusBadRequest, "unsupported protocol version")
		return nil, false
	}
	chainID, err1 := kauri.B64.DecodeString(r.Header.Get(kauri.HeaderChain))
	pub, err2 := kauri.B64.DecodeString(r.Header.Get(kauri.HeaderDevice))
	sig, err3 := kauri.B64.DecodeString(r.Header.Get(kauri.HeaderSignature))
	unix, err4 := strconv.ParseInt(r.Header.Get(kauri.HeaderTime), 10, 64)
	nonce, err5 := kauri.B64.DecodeString(r.Header.Get(kauri.HeaderNonce))
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || len(chainID) != 32 || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || len(nonce) != 16 {
		return unauthorized("missing or malformed signature headers")
	}
	now := a.Now()
	if d := now.Sub(time.Unix(unix, 0)); d > a.ClockSkew || d < -a.ClockSkew {
		return unauthorized("the request time is too far from the server's clock")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.bodyLimit(r)))
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	if !kauri.VerifyRequest(pub, r.Method, r.URL.RequestURI(), unix, nonce, body, sig) {
		return unauthorized("bad signature")
	}
	sigHash := sha256.Sum256(sig)
	fresh, err := a.Store.UseSignature(r.Context(), sigHash[:], now.Add(2*a.ClockSkew))
	if err != nil {
		a.internal(w, err)
		return nil, false
	}
	if !fresh {
		return unauthorized("the signature was used already")
	}
	hash := kauri.IDHash(chainID)
	c := &caller{chainID: chainID, chain: hash[:], devicePub: pub, deviceID: kauri.DeviceID(pub), body: body}

	row, err := a.Store.Chain(r.Context(), c.chain)
	switch {
	case m == modeCreate:
		if err == nil {
			fail(w, http.StatusConflict, "the chain exists")
			return nil, false
		}
		if !errors.Is(err, store.ErrNoChain) {
			a.internal(w, err)
			return nil, false
		}
		return c, true
	case errors.Is(err, store.ErrNoChain):
		fail(w, http.StatusNotFound, "no such chain")
		return nil, false
	case err != nil:
		a.internal(w, err)
		return nil, false
	}
	c.row = row
	if row.Forwarded && m != modeForwarded {
		fail(w, http.StatusGone, "forwarded")
		return nil, false
	}
	dev, err := a.Store.Device(r.Context(), c.chain, c.deviceID)
	switch {
	case errors.Is(err, store.ErrNoDevice):
		if m == modeJoin {
			return c, true
		}
		return unauthorized("this device is not in the chain")
	case err != nil:
		a.internal(w, err)
		return nil, false
	}
	if dev.Removed != nil {
		fail(w, http.StatusForbidden, "this device was removed from the chain")
		return nil, false
	}
	c.member = true
	return c, true
}

func (a *API) internal(w http.ResponseWriter, err error) {
	a.Log.Error("request failed", "error", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

func decode(w http.ResponseWriter, c *caller, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(c.body))
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return false
	}
	return true
}

func (a *API) publish(ctx context.Context, c *caller, kind string, data any, target []byte) {
	if a.Hub == nil {
		return
	}
	b, _ := json.Marshal(data)
	e := events.Event{Kind: kind, Data: b, Chain: c.chain, Target: target}
	if target == nil {
		e.Origin = c.deviceID
	}
	a.Hub.Publish(context.WithoutCancel(ctx), e)
}

// ---- chains and devices ----

type deviceInfo struct {
	Sign   Bytes `json:"sign"`
	X25519 Bytes `json:"x25519"`
	MLKEM  Bytes `json:"mlkem"`
	Name   Bytes `json:"name"`
}

func (d deviceInfo) valid() error {
	switch {
	case len(d.Sign) != ed25519.PublicKeySize:
		return errors.New("device.sign must be 32 bytes")
	case len(d.X25519) != 32:
		return errors.New("device.x25519 must be 32 bytes")
	case len(d.MLKEM) != 0 && len(d.MLKEM) != 1184:
		return errors.New("device.mlkem must be empty or 1184 bytes")
	case len(d.Name) == 0 || len(d.Name) > 512:
		return errors.New("device.name must be 1 to 512 bytes")
	}
	return nil
}

func (d deviceInfo) row() store.Device {
	return store.Device{ID: kauri.DeviceID(ed25519.PublicKey(d.Sign)), Sign: d.Sign, X25519: d.X25519, MLKEM: d.MLKEM, Name: d.Name}
}

const maxEnvelope = 1 + 32 + 1088 + 24 + 32 + 16

func (a *API) createChain(w http.ResponseWriter, r *http.Request, c *caller) {
	if !allow(w, a.ChainCreates, addrKey(r)) {
		return
	}
	var req struct {
		ChainKey Bytes      `json:"chain_key"`
		ChainSig Bytes      `json:"chain_sig"`
		Device   deviceInfo `json:"device"`
		Keyring  struct {
			Epoch    int   `json:"epoch"`
			Wrapped  Bytes `json:"wrapped"`
			Envelope Bytes `json:"envelope"`
		} `json:"keyring"`
	}
	if !decode(w, c, &req) {
		return
	}
	if err := req.Device.valid(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case !bytes.Equal(req.Device.Sign, c.devicePub):
		fail(w, http.StatusBadRequest, "device.sign must be the signing device")
		return
	case len(req.ChainKey) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(req.ChainKey), kauri.AddMessage(c.chainID, c.devicePub), req.ChainSig):
		fail(w, http.StatusUnauthorized, "bad chain_sig")
		return
	case req.Keyring.Epoch != 1 || len(req.Keyring.Wrapped) != 24+32+16 || len(req.Keyring.Envelope) == 0 || len(req.Keyring.Envelope) > maxEnvelope:
		fail(w, http.StatusBadRequest, "bad keyring")
		return
	}
	err := a.Store.CreateChain(r.Context(), c.chain, req.ChainKey, req.Device.row(), req.Keyring.Wrapped, req.Keyring.Envelope)
	switch {
	case errors.Is(err, store.ErrChainExists):
		fail(w, http.StatusConflict, "the chain exists")
	case err != nil:
		a.internal(w, err)
	default:
		w.WriteHeader(http.StatusCreated)
	}
}

func (a *API) addDevice(w http.ResponseWriter, r *http.Request, c *caller) {
	var req struct {
		Device   deviceInfo `json:"device"`
		ChainSig Bytes      `json:"chain_sig"`
		Envelope Bytes      `json:"envelope"`
	}
	if !decode(w, c, &req) {
		return
	}
	if err := req.Device.valid(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Envelope) > maxEnvelope {
		fail(w, http.StatusBadRequest, "envelope too large")
		return
	}
	if !c.member {
		// Recovery from the sync code: the device adds itself with chain_sig.
		if !bytes.Equal(req.Device.Sign, c.devicePub) || len(req.Envelope) != 0 ||
			!ed25519.Verify(ed25519.PublicKey(c.row.AuthKey), kauri.AddMessage(c.chainID, c.devicePub), req.ChainSig) {
			fail(w, http.StatusUnauthorized, "a new device must sign for itself with chain_sig")
			return
		}
	}
	var env []byte
	if len(req.Envelope) > 0 {
		env = req.Envelope
	}
	err := a.Store.AddDevice(r.Context(), c.chain, req.Device.row(), env)
	switch {
	case errors.Is(err, store.ErrNoDevice):
		fail(w, http.StatusForbidden, "this device was removed from the chain")
	case errors.Is(err, store.ErrForwarded):
		fail(w, http.StatusGone, "forwarded")
	case err != nil:
		a.internal(w, err)
	default:
		a.publish(r.Context(), c, "devices", struct{}{}, nil)
		w.WriteHeader(http.StatusCreated)
	}
}

type deviceOut struct {
	ID      Bytes  `json:"id"`
	Sign    Bytes  `json:"sign"`
	X25519  Bytes  `json:"x25519"`
	MLKEM   Bytes  `json:"mlkem"`
	Name    Bytes  `json:"name"`
	Added   int64  `json:"added"`
	Removed *int64 `json:"removed"`
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request, c *caller) {
	devs, err := a.Store.Devices(r.Context(), c.chain)
	if err != nil {
		a.internal(w, err)
		return
	}
	out := make([]deviceOut, 0, len(devs))
	for _, d := range devs {
		o := deviceOut{ID: d.ID, Sign: d.Sign, X25519: d.X25519, MLKEM: d.MLKEM, Name: d.Name, Added: d.Added.Unix()}
		if d.Removed != nil {
			t := d.Removed.Unix()
			o.Removed = &t
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func pathBytes(w http.ResponseWriter, r *http.Request, name string, n int) ([]byte, bool) {
	b, err := kauri.B64.DecodeString(r.PathValue(name))
	if err != nil || len(b) != n {
		fail(w, http.StatusBadRequest, fmt.Sprintf("%s must be %d bytes of base64url", name, n))
		return nil, false
	}
	return b, true
}

func (a *API) removeDevice(w http.ResponseWriter, r *http.Request, c *caller) {
	id, ok := pathBytes(w, r, "id", 16)
	if !ok {
		return
	}
	err := a.Store.RemoveDevice(r.Context(), c.chain, id)
	switch {
	case errors.Is(err, store.ErrNoDevice):
		fail(w, http.StatusNotFound, "no such device")
	case err != nil:
		a.internal(w, err)
	default:
		a.publish(r.Context(), c, "removed", struct{}{}, id)
		a.publish(r.Context(), c, "devices", struct{}{}, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- keyring ----

func (a *API) keyring(w http.ResponseWriter, r *http.Request, c *caller) {
	epoch, wrapped, env, err := a.Store.Keyring(r.Context(), c.chain, c.deviceID)
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"epoch": epoch, "wrapped": Bytes(wrapped), "envelope": Bytes(env)})
}

type envelopeIn struct {
	Device   Bytes `json:"device"`
	Envelope Bytes `json:"envelope"`
}

func envelopes(in []envelopeIn) ([]store.Envelope, error) {
	if len(in) > 1000 {
		return nil, errors.New("too many envelopes")
	}
	out := make([]store.Envelope, 0, len(in))
	for _, e := range in {
		if len(e.Device) != 16 || len(e.Envelope) == 0 || len(e.Envelope) > maxEnvelope {
			return nil, errors.New("bad envelope")
		}
		out = append(out, store.Envelope{Device: e.Device, Envelope: e.Envelope})
	}
	return out, nil
}

func (a *API) newEpoch(w http.ResponseWriter, r *http.Request, c *caller) {
	var req struct {
		Epoch     int          `json:"epoch"`
		Wrapped   Bytes        `json:"wrapped"`
		Envelopes []envelopeIn `json:"envelopes"`
	}
	if !decode(w, c, &req) {
		return
	}
	envs, err := envelopes(req.Envelopes)
	if err != nil || len(req.Wrapped) != 24+32+16 {
		fail(w, http.StatusBadRequest, "bad keyring")
		return
	}
	err = a.Store.NewEpoch(r.Context(), c.chain, req.Epoch, req.Wrapped, envs)
	switch {
	case errors.Is(err, store.ErrEpoch):
		fail(w, http.StatusConflict, "epoch must be the current one plus 1")
	case err != nil:
		a.internal(w, err)
	default:
		a.publish(r.Context(), c, "keyring", map[string]int{"epoch": req.Epoch}, nil)
		w.WriteHeader(http.StatusCreated)
	}
}

// ---- records ----

type recordOut struct {
	ID      Bytes `json:"id"`
	Version int64 `json:"version"`
	Epoch   int   `json:"epoch"`
	Deleted bool  `json:"deleted"`
	Body    Bytes `json:"body"`
}

func (a *API) changes(w http.ResponseWriter, r *http.Request, c *caller) {
	q := r.URL.Query()
	since, err := strconv.ParseInt(q.Get("since"), 10, 64)
	if q.Get("since") == "" {
		since, err = 0, nil
	}
	limit := 500
	if l := q.Get("limit"); l != "" {
		limit, err = strconv.Atoi(l)
	}
	if err != nil || since < 0 || limit < 1 {
		fail(w, http.StatusBadRequest, "bad since or limit")
		return
	}
	limit = min(limit, 1000)
	version, recs, more, err := a.Store.Changes(r.Context(), c.chain, since, limit)
	switch {
	case errors.Is(err, store.ErrResync):
		fail(w, http.StatusGone, "resync")
		return
	case errors.Is(err, store.ErrForwarded):
		fail(w, http.StatusGone, "forwarded")
		return
	case err != nil:
		a.internal(w, err)
		return
	}
	out := make([]recordOut, len(recs))
	for i, x := range recs {
		out[i] = recordOut{ID: x.ID, Version: x.Version, Epoch: x.Epoch, Deleted: x.Deleted, Body: x.Body}
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": version, "records": out, "more": more})
}

const maxBody = 24 + 65536 + 16

func (a *API) writeRecords(w http.ResponseWriter, r *http.Request, c *caller) {
	var req struct {
		Records []struct {
			ID        Bytes   `json:"id"`
			Epoch     int     `json:"epoch"`
			Body      Bytes   `json:"body"`
			Deleted   bool    `json:"deleted"`
			Blobs     []Bytes `json:"blobs"`
			IfVersion *int64  `json:"if_version"`
		} `json:"records"`
	}
	if !decode(w, c, &req) {
		return
	}
	if len(req.Records) == 0 || len(req.Records) > a.MaxBatchRecords {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("a batch has 1 to %d records", a.MaxBatchRecords))
		return
	}
	writes := make([]store.Write, len(req.Records))
	seen := map[string]bool{}
	var total int64
	for i, x := range req.Records {
		if len(x.ID) != 16 || len(x.Body) < 24+16+256 || len(x.Body) > maxBody || x.Epoch < 1 || len(x.Blobs) > 64 || seen[string(x.ID)] {
			fail(w, http.StatusBadRequest, fmt.Sprintf("record %d is malformed", i))
			return
		}
		seen[string(x.ID)] = true
		total += int64(len(x.Body))
		blobs := make([][]byte, len(x.Blobs))
		for j, b := range x.Blobs {
			if len(b) != 16 {
				fail(w, http.StatusBadRequest, fmt.Sprintf("record %d lists a malformed blob id", i))
				return
			}
			blobs[j] = b
		}
		writes[i] = store.Write{ID: x.ID, Epoch: x.Epoch, Deleted: x.Deleted, Body: x.Body, Blobs: blobs, IfVersion: x.IfVersion}
	}
	if total > a.MaxBatchBytes {
		fail(w, http.StatusRequestEntityTooLarge, "the batch is too large")
		return
	}
	versions, err := a.Store.WriteRecords(r.Context(), c.chain, writes, store.Limits{MaxBytes: a.MaxBytesPerChain, MaxRecords: a.MaxRecords})
	var conflict *store.ConflictError
	switch {
	case errors.As(err, &conflict):
		ids := make([]Bytes, len(conflict.IDs))
		for i, id := range conflict.IDs {
			ids[i] = id
		}
		writeJSON(w, http.StatusConflict, map[string]any{"error": "conflict", "conflicts": ids})
	case errors.Is(err, store.ErrLimit):
		fail(w, http.StatusRequestEntityTooLarge, "the chain is full")
	case errors.Is(err, store.ErrEpoch):
		fail(w, http.StatusBadRequest, "unknown epoch")
	case errors.Is(err, store.ErrMissingBlob):
		fail(w, http.StatusBadRequest, "a listed blob is not uploaded")
	case errors.Is(err, store.ErrForwarded):
		fail(w, http.StatusGone, "forwarded")
	case err != nil:
		a.internal(w, err)
	default:
		a.publish(r.Context(), c, "changed", map[string]int64{"version": versions[len(versions)-1]}, nil)
		writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
	}
}

// ---- blobs ----

func (a *API) putBlob(w http.ResponseWriter, r *http.Request, c *caller) {
	id, ok := pathBytes(w, r, "id", 16)
	if !ok {
		return
	}
	if int64(len(c.body)) > a.MaxBlobBytes+24+16+65536 || len(c.body) < 24+16+65536 || (len(c.body)-40)%65536 != 0 {
		fail(w, http.StatusBadRequest, "a blob is a padded ciphertext up to the blob size limit")
		return
	}
	err := a.Store.PutBlob(r.Context(), c.chain, id, c.body, store.Limits{MaxBytes: a.MaxBytesPerChain})
	switch {
	case errors.Is(err, store.ErrLimit):
		fail(w, http.StatusRequestEntityTooLarge, "the chain is full")
	case errors.Is(err, store.ErrForwarded):
		fail(w, http.StatusGone, "forwarded")
	case err != nil:
		a.internal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) getBlob(w http.ResponseWriter, r *http.Request, c *caller) {
	id, ok := pathBytes(w, r, "id", 16)
	if !ok {
		return
	}
	data, found, err := a.Store.Blob(r.Context(), c.chain, id)
	switch {
	case err != nil:
		a.internal(w, err)
	case !found:
		fail(w, http.StatusNotFound, "no such blob")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	}
}

// ---- forwarding (§9) ----

func (a *API) forward(w http.ResponseWriter, r *http.Request, c *caller) {
	var req struct {
		Envelopes []envelopeIn `json:"envelopes"`
	}
	if !decode(w, c, &req) {
		return
	}
	envs, err := envelopes(req.Envelopes)
	if err != nil || len(envs) == 0 {
		fail(w, http.StatusBadRequest, "bad envelopes")
		return
	}
	switch err := a.Store.Forward(r.Context(), c.chain, envs); {
	case errors.Is(err, store.ErrForwarded):
		fail(w, http.StatusGone, "forwarded")
	case err != nil:
		a.internal(w, err)
	default:
		a.publish(r.Context(), c, "forwarded", struct{}{}, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) getForward(w http.ResponseWriter, r *http.Request, c *caller) {
	if !c.row.Forwarded {
		fail(w, http.StatusNotFound, "the chain has not moved")
		return
	}
	env, err := a.Store.ForwardEnvelope(r.Context(), c.chain, c.deviceID)
	switch {
	case errors.Is(err, store.ErrNoDevice):
		fail(w, http.StatusNotFound, "no envelope for this device")
	case err != nil:
		a.internal(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"envelope": Bytes(env)})
	}
}

func jsonDecode(r io.Reader, v any) error { return json.NewDecoder(r).Decode(v) }
