// Package events wakes a chain's devices when something changes (§7.3).
// With a Postgres pool, events go through NOTIFY so that every server
// instance delivers them to the devices connected to it.
package events

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const channel = "kauri_sync"

// Event is delivered to the devices of a chain.
type Event struct {
	Kind string          `json:"k"`
	Data json.RawMessage `json:"d"`
	// Origin is the device that caused the event; it is not told.
	Origin []byte `json:"o,omitempty"`
	// Target, if set, is the only device that gets the event.
	Target []byte `json:"t,omitempty"`
	Chain  []byte `json:"c"`
}

// Subscriber receives a chain's events for one device.
type Subscriber struct {
	C      chan Event
	device []byte
	chain  string
}

// Hub delivers events.
type Hub struct {
	pool *pgxpool.Pool
	log  *slog.Logger
	// MaxPerChain limits open streams per chain; 0 for no limit.
	MaxPerChain int

	mu   sync.Mutex
	subs map[string]map[*Subscriber]struct{}
}

// New makes a hub. pool may be nil for a single instance.
func New(pool *pgxpool.Pool, log *slog.Logger, maxPerChain int) *Hub {
	return &Hub{pool: pool, log: log, MaxPerChain: maxPerChain, subs: map[string]map[*Subscriber]struct{}{}}
}

// Publish sends an event to a chain's devices.
func (h *Hub) Publish(ctx context.Context, e Event) {
	if h.pool == nil {
		h.dispatch(e)
		return
	}
	b, _ := json.Marshal(e)
	if _, err := h.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, channel, string(b)); err != nil {
		h.log.Warn("notify failed, delivering locally", "error", err)
		h.dispatch(e)
	}
}

// Listen receives NOTIFY events until ctx ends, reconnecting on errors.
func (h *Hub) Listen(ctx context.Context) {
	if h.pool == nil {
		return
	}
	for ctx.Err() == nil {
		if err := h.listen(ctx); err != nil && ctx.Err() == nil {
			h.log.Warn("event listener stopped; reconnecting", "error", err)
			// Devices may have missed events: tell everyone to refetch.
			h.broadcast(Event{Kind: "changed", Data: json.RawMessage(`{"version":0}`)})
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func (h *Hub) listen(ctx context.Context) error {
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var e Event
		if json.Unmarshal([]byte(n.Payload), &e) == nil {
			h.dispatch(e)
		}
	}
}

func (h *Hub) dispatch(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs[hex.EncodeToString(e.Chain)] {
		if e.Origin != nil && bytes.Equal(e.Origin, s.device) {
			continue
		}
		if e.Target != nil && !bytes.Equal(e.Target, s.device) {
			continue
		}
		select {
		case s.C <- e:
		default: // the device is slow; it refetches on the next event anyway
		}
	}
}

func (h *Hub) broadcast(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, set := range h.subs {
		for s := range set {
			select {
			case s.C <- e:
			default:
			}
		}
	}
}

// Subscribe opens a stream for a device. ok is false over the limit.
func (h *Hub) Subscribe(chain, device []byte) (*Subscriber, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := hex.EncodeToString(chain)
	set := h.subs[key]
	if h.MaxPerChain > 0 && len(set) >= h.MaxPerChain {
		return nil, false
	}
	if set == nil {
		set = map[*Subscriber]struct{}{}
		h.subs[key] = set
	}
	s := &Subscriber{C: make(chan Event, 32), device: device, chain: key}
	set[s] = struct{}{}
	return s, true
}

// Unsubscribe closes a stream.
func (h *Hub) Unsubscribe(s *Subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs[s.chain], s)
	if len(h.subs[s.chain]) == 0 {
		delete(h.subs, s.chain)
	}
}

// Streams is the number of open streams.
func (h *Hub) Streams() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, s := range h.subs {
		n += len(s)
	}
	return n
}
