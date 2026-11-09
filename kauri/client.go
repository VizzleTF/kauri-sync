package kauri

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client talks to a Kauri Sync server as one device of one chain.
type Client struct {
	Server string // e.g. https://sync.example.com
	Chain  *Chain
	Device *Device
	HTTP   *http.Client
	// Now is the clock used for signatures.
	Now func() time.Time
	// Nonce, if set, is used for every request instead of a random one (tests).
	Nonce []byte
}

// APIError is a non-2xx answer.
type APIError struct {
	Status int
	Msg    string
	Body   []byte
}

func (e *APIError) Error() string { return fmt.Sprintf("kauri-sync: %d %s", e.Status, e.Msg) }

// StatusOf returns the HTTP status of an APIError, or 0.
func StatusOf(err error) int {
	var e *APIError
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Do sends a signed request and decodes a JSON answer into out (if not nil).
func (c *Client) Do(ctx context.Context, method, path string, body []byte, out any) error {
	resp, err := c.send(ctx, method, path, body, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return &APIError{Status: resp.StatusCode, Msg: e.Error, Body: data}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) send(ctx context.Context, method, path string, body []byte, ctype string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Server, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	unix := c.now().Unix()
	nonce := make([]byte, 16)
	if c.Nonce != nil {
		copy(nonce, c.Nonce)
	} else if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req.Header.Set(HeaderProtocol, strconv.Itoa(Protocol))
	req.Header.Set(HeaderNonce, B64.EncodeToString(nonce))
	req.Header.Set(HeaderChain, B64.EncodeToString(c.Chain.ID[:]))
	req.Header.Set(HeaderDevice, B64.EncodeToString(c.Device.Public()))
	req.Header.Set(HeaderTime, strconv.FormatInt(unix, 10))
	req.Header.Set(HeaderSignature, B64.EncodeToString(c.Device.SignRequest(method, req.URL.RequestURI(), unix, nonce, body)))
	if body != nil {
		req.Header.Set("Content-Type", ctype)
	}
	return c.http().Do(req)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func b64(b []byte) string { return B64.EncodeToString(b) }

// DeviceInfo is this device's info object (§7.2).
func (c *Client) DeviceInfo(name string) map[string]string {
	r := c.Device.Recipient()
	return map[string]string{
		"sign": b64(c.Device.Public()), "x25519": b64(r.X25519), "mlkem": b64(r.MLKEM),
		"name": b64(c.Chain.SealName(c.Device.ID(), name)),
	}
}

// CreateChain registers a new chain with this device and a fresh data key.
func (c *Client) CreateChain(ctx context.Context, name string) ([32]byte, error) {
	dk := NewDataKey()
	env, err := SealEnvelope(c.Chain.ID[:], 1, c.Device.Recipient(), dk[:])
	if err != nil {
		return dk, err
	}
	body := mustJSON(map[string]any{
		"chain_key": b64(c.Chain.AuthPublic()),
		"chain_sig": b64(c.Chain.AddSignature(c.Device.Public())),
		"device":    c.DeviceInfo(name),
		"keyring":   map[string]any{"epoch": 1, "wrapped": b64(c.Chain.WrapDataKey(dk, 1)), "envelope": b64(env)},
	})
	return dk, c.Do(ctx, "POST", "/v1/chains", body, nil)
}

// JoinWithCode adds this device to an existing chain from the sync code.
func (c *Client) JoinWithCode(ctx context.Context, name string) error {
	body := mustJSON(map[string]any{
		"device":    c.DeviceInfo(name),
		"chain_sig": b64(c.Chain.AddSignature(c.Device.Public())),
	})
	return c.Do(ctx, "POST", "/v1/devices", body, nil)
}

// Keyring is the current epoch and this device's way to its data key.
type Keyring struct {
	Epoch    uint32 `json:"epoch"`
	Wrapped  string `json:"wrapped"`
	Envelope string `json:"envelope"`
}

// DataKey fetches the keyring and opens the data key, from the envelope if
// there is one, otherwise from the wrapped copy.
func (c *Client) DataKey(ctx context.Context) (uint32, [32]byte, error) {
	var k Keyring
	var dk [32]byte
	if err := c.Do(ctx, "GET", "/v1/keyring", nil, &k); err != nil {
		return 0, dk, err
	}
	if k.Envelope != "" {
		env, err := B64.DecodeString(k.Envelope)
		if err != nil {
			return 0, dk, err
		}
		p, err := c.Device.OpenEnvelope(c.Chain.ID[:], k.Epoch, env)
		if err == nil && len(p) == 32 {
			copy(dk[:], p)
			return k.Epoch, dk, nil
		}
	}
	w, err := B64.DecodeString(k.Wrapped)
	if err != nil {
		return 0, dk, err
	}
	dk, err = c.Chain.UnwrapDataKey(w, k.Epoch)
	return k.Epoch, dk, err
}

// RecordIn is one record of a write.
type RecordIn struct {
	ID        []byte
	Epoch     uint32
	Body      []byte
	Deleted   bool
	Blobs     [][]byte
	IfVersion *int64
}

// WriteRecords writes a batch and returns the new versions.
func (c *Client) WriteRecords(ctx context.Context, recs []RecordIn) ([]int64, error) {
	list := make([]map[string]any, len(recs))
	for i, r := range recs {
		m := map[string]any{"id": b64(r.ID), "epoch": r.Epoch, "body": b64(r.Body), "deleted": r.Deleted}
		if len(r.Blobs) > 0 {
			bs := make([]string, len(r.Blobs))
			for j, b := range r.Blobs {
				bs[j] = b64(b)
			}
			m["blobs"] = bs
		}
		if r.IfVersion != nil {
			m["if_version"] = *r.IfVersion
		}
		list[i] = m
	}
	var out struct {
		Versions []int64 `json:"versions"`
	}
	err := c.Do(ctx, "POST", "/v1/records", mustJSON(map[string]any{"records": list}), &out)
	return out.Versions, err
}

// RecordOut is a record from /v1/changes.
type RecordOut struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	Epoch   uint32 `json:"epoch"`
	Deleted bool   `json:"deleted"`
	Body    string `json:"body"`
}

// Changes is an answer of /v1/changes.
type Changes struct {
	Version int64       `json:"version"`
	Records []RecordOut `json:"records"`
	More    bool        `json:"more"`
}

// Changes fetches records after since.
func (c *Client) Changes(ctx context.Context, since int64, limit int) (Changes, error) {
	var out Changes
	err := c.Do(ctx, "GET", fmt.Sprintf("/v1/changes?since=%d&limit=%d", since, limit), nil, &out)
	return out, err
}

// PutBlob uploads a sealed blob.
func (c *Client) PutBlob(ctx context.Context, id, sealed []byte) error {
	resp, err := c.send(ctx, "PUT", "/v1/blobs/"+b64(id), sealed, "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		data, _ := io.ReadAll(resp.Body)
		return &APIError{Status: resp.StatusCode, Body: data}
	}
	return nil
}

// GetBlob downloads a sealed blob.
func (c *Client) GetBlob(ctx context.Context, id []byte) ([]byte, error) {
	resp, err := c.send(ctx, "GET", "/v1/blobs/"+b64(id), nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Body: data}
	}
	return data, nil
}

// Event is one Server-Sent Event.
type Event struct {
	Kind string
	Data string
}

// Events opens the event stream; events arrive on the channel until ctx ends
// or the stream closes.
func (c *Client) Events(ctx context.Context) (<-chan Event, error) {
	resp, err := c.send(ctx, "GET", "/v1/events", nil, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, &APIError{Status: resp.StatusCode}
	}
	ch := make(chan Event, 16)
	go func() {
		defer resp.Body.Close()
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		var e Event
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				e.Kind = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				e.Data = strings.TrimPrefix(line, "data: ")
			case line == "" && e.Kind != "":
				select {
				case ch <- e:
				case <-ctx.Done():
					return
				}
				e = Event{}
			}
		}
	}()
	return ch, nil
}

// ---- pairing ----

// PairSlotState is GET /v1/pair/{slot}.
type PairSlotState struct {
	Msg      string `json:"msg"`
	Joined   bool   `json:"joined"`
	BMsg     string `json:"bmsg"`
	Confirm  string `json:"confirm"`
	Box      string `json:"box"`
	Approval string `json:"approval"`
	Expires  int    `json:"expires"`
}

// PairOpen opens a slot as the existing device.
func (c *Client) PairOpen(ctx context.Context, p *Pairing) error {
	return c.Do(ctx, "POST", "/v1/pair", mustJSON(map[string]string{"slot": p.Slot, "msg": b64(p.Msg)}), nil)
}

// PairApprove sends the sealed chain secret.
func (c *Client) PairApprove(ctx context.Context, slot string, box []byte) error {
	return c.Do(ctx, "POST", "/v1/pair/"+slot+"/approve", mustJSON(map[string]string{"box": b64(box)}), nil)
}

// AddDevice adds another device (as a member) with its envelope for the
// current epoch.
func (c *Client) AddDevice(ctx context.Context, info map[string]string, epoch uint32, dk [32]byte) error {
	sign, _ := B64.DecodeString(info["sign"])
	x, _ := B64.DecodeString(info["x25519"])
	ml, _ := B64.DecodeString(info["mlkem"])
	env, err := SealEnvelope(c.Chain.ID[:], epoch, Recipient{ID: DeviceID(sign), X25519: x, MLKEM: ml}, dk[:])
	if err != nil {
		return err
	}
	return c.Do(ctx, "POST", "/v1/devices", mustJSON(map[string]any{"device": info, "envelope": b64(env)}), nil)
}

// Unsigned requests for the new device during pairing.

// PairGet reads a slot.
func PairGet(ctx context.Context, server, slot string) (PairSlotState, error) {
	var s PairSlotState
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(server, "/")+"/v1/pair/"+slot, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s, &APIError{Status: resp.StatusCode}
	}
	return s, json.NewDecoder(resp.Body).Decode(&s)
}

// PairJoin answers a slot as the new device.
func PairJoin(ctx context.Context, server, slot string, msg, confirm, box []byte) error {
	body := mustJSON(map[string]string{"msg": b64(msg), "confirm": b64(confirm), "box": b64(box)})
	req, _ := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(server, "/")+"/v1/pair/"+slot+"/join", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return &APIError{Status: resp.StatusCode}
	}
	return nil
}

// SlotHex checks that a slot is 64 hex digits.
func SlotHex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}
