package api

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/VizzleTF/kauri-sync/internal/store"
)

const (
	heartbeat    = 25 * time.Second
	writeTimeout = 30 * time.Second
)

// events serves the Server-Sent Events stream (§7.3).
func (a *API) events(w http.ResponseWriter, r *http.Request, c *caller) {
	if a.Hub == nil {
		fail(w, http.StatusServiceUnavailable, "events are off")
		return
	}
	sub, ok := a.Hub.Subscribe(c.chain, c.deviceID)
	if !ok {
		tooMany(w, time.Minute)
		return
	}
	defer a.Hub.Unsubscribe(sub)
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(format string, args ...any) error {
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return err
		}
		return rc.Flush()
	}
	if send("retry: 5000\nevent: ready\ndata: {}\n\n") != nil {
		return
	}
	tick := time.NewTicker(heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if send(": keep-alive\n\n") != nil {
				return
			}
		case e := <-sub.C:
			if send("event: %s\ndata: %s\n\n", e.Kind, e.Data) != nil {
				return
			}
			if e.Kind == "removed" || e.Kind == "forwarded" {
				return
			}
		}
	}
}

// ---- pairing (§8) ----

type slotOut struct {
	Msg      Bytes `json:"msg"`
	Joined   bool  `json:"joined"`
	BMsg     Bytes `json:"bmsg,omitempty"`
	Confirm  Bytes `json:"confirm,omitempty"`
	Box      Bytes `json:"box,omitempty"`
	Approval Bytes `json:"approval,omitempty"`
	Expires  int   `json:"expires"`
}

func validSlot(w http.ResponseWriter, id string) bool {
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != id {
		fail(w, http.StatusBadRequest, "slot must be 64 lowercase hex digits")
		return false
	}
	return true
}

func (a *API) slotError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNoSlot):
		fail(w, http.StatusNotFound, "no such pairing code, or it expired")
	case errors.Is(err, store.ErrSlotUsed):
		fail(w, http.StatusConflict, "the pairing code was used already")
	case errors.Is(err, store.ErrSlotTaken):
		fail(w, http.StatusConflict, "the slot is taken; make a new code")
	case err != nil:
		a.internal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) pairOpen(w http.ResponseWriter, r *http.Request, c *caller) {
	if !allow(w, a.PairOpens, hex.EncodeToString(c.chain)) {
		return
	}
	var req struct {
		Slot string `json:"slot"`
		Msg  Bytes  `json:"msg"`
	}
	if !decode(w, c, &req) || !validSlot(w, req.Slot) {
		return
	}
	if len(req.Msg) != 32 {
		fail(w, http.StatusBadRequest, "msg must be 32 bytes")
		return
	}
	a.slotError(w, a.Store.CreatePairSlot(r.Context(), store.PairSlot{ID: req.Slot, Chain: c.chain, AMsg: req.Msg}, a.PairTTL))
}

func (a *API) pairGet(w http.ResponseWriter, r *http.Request) {
	if !allow(w, a.PairReads, addrKey(r)) {
		return
	}
	id := r.PathValue("slot")
	if !validSlot(w, id) {
		return
	}
	s, err := a.Store.PairSlot(r.Context(), id, a.PairTTL)
	if err != nil {
		a.slotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, slotOut{
		Msg: s.AMsg, Joined: s.BMsg != nil, BMsg: s.BMsg, Confirm: s.Confirm, Box: s.BBox, Approval: s.Approval,
		Expires: int(max(0, time.Until(s.Created.Add(a.PairTTL)).Seconds())),
	})
}

func (a *API) pairJoin(w http.ResponseWriter, r *http.Request) {
	if !allow(w, a.PairJoins, addrKey(r)) {
		return
	}
	id := r.PathValue("slot")
	if !validSlot(w, id) {
		return
	}
	var req struct {
		Msg     Bytes `json:"msg"`
		Confirm Bytes `json:"confirm"`
		Box     Bytes `json:"box"`
	}
	if err := decodeLimited(r, w, &req); err != nil {
		return
	}
	if len(req.Msg) != 32 || len(req.Confirm) != 32 || len(req.Box) < 40 || len(req.Box) > 4096 {
		fail(w, http.StatusBadRequest, "msg and confirm must be 32 bytes, box up to 4096")
		return
	}
	a.slotError(w, a.Store.JoinPairSlot(r.Context(), id, req.Msg, req.Confirm, req.Box, a.PairTTL))
}

func (a *API) pairApprove(w http.ResponseWriter, r *http.Request, c *caller) {
	id := r.PathValue("slot")
	if !validSlot(w, id) {
		return
	}
	var req struct {
		Box Bytes `json:"box"`
	}
	if !decode(w, c, &req) {
		return
	}
	if len(req.Box) != 24+32+16 {
		fail(w, http.StatusBadRequest, "box must be 72 bytes")
		return
	}
	a.slotError(w, a.Store.ApprovePairSlot(r.Context(), id, c.chain, req.Box, a.PairTTL))
}

func (a *API) pairDelete(w http.ResponseWriter, r *http.Request, c *caller) {
	id := r.PathValue("slot")
	if !validSlot(w, id) {
		return
	}
	a.slotError(w, a.Store.DeletePairSlot(r.Context(), id, c.chain))
}

func decodeLimited(r *http.Request, w http.ResponseWriter, v any) error {
	err := jsonDecode(http.MaxBytesReader(w, r.Body, 16<<10), v)
	if err != nil {
		fail(w, http.StatusBadRequest, "malformed request")
	}
	return err
}
