// Package store keeps sync chains in PostgreSQL. It stores only what
// docs/sync.md lets the server see: hashed chain IDs, public keys, opaque
// ciphertext, versions and sizes.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNoChain     = errors.New("no such chain")
	ErrChainExists = errors.New("the chain exists")
	ErrForwarded   = errors.New("the chain moved")
	ErrNoDevice    = errors.New("no such device")
	ErrEpoch       = errors.New("wrong epoch")
	ErrMissingBlob = errors.New("a listed blob is not uploaded")
	ErrLimit       = errors.New("over a limit")
	ErrResync      = errors.New("resync required")
	ErrNoSlot      = errors.New("no such pairing slot")
	ErrSlotTaken   = errors.New("the pairing slot is taken")
	ErrSlotUsed    = errors.New("the pairing slot is used")
)

// ConflictError lists the records whose if_version did not match.
type ConflictError struct{ IDs [][]byte }

func (e *ConflictError) Error() string { return fmt.Sprintf("%d conflicting records", len(e.IDs)) }

// Limits are the per-chain limits.
type Limits struct {
	MaxBytes   int64
	MaxRecords int64
}

// Store is the Postgres store.
type Store struct {
	Pool *pgxpool.Pool
}

// New wraps a pool.
func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

const schema = `
CREATE TABLE IF NOT EXISTS chains (
	id         bytea PRIMARY KEY,
	auth_key   bytea NOT NULL,
	version    bigint NOT NULL DEFAULT 0,
	bytes      bigint NOT NULL DEFAULT 0,
	records    bigint NOT NULL DEFAULT 0,
	horizon    bigint NOT NULL DEFAULT 0,
	epoch      integer NOT NULL DEFAULT 1,
	forwarded  timestamptz,
	created    timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS devices (
	chain    bytea NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
	id       bytea NOT NULL,
	sign     bytea NOT NULL,
	x25519   bytea NOT NULL,
	mlkem    bytea NOT NULL,
	name     bytea NOT NULL,
	added    timestamptz NOT NULL DEFAULT now(),
	removed  timestamptz,
	PRIMARY KEY (chain, id)
);
CREATE TABLE IF NOT EXISTS keyrings (
	chain    bytea NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
	epoch    integer NOT NULL,
	wrapped  bytea NOT NULL,
	PRIMARY KEY (chain, epoch)
);
CREATE TABLE IF NOT EXISTS envelopes (
	chain    bytea NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
	epoch    integer NOT NULL,
	device   bytea NOT NULL,
	envelope bytea NOT NULL,
	PRIMARY KEY (chain, epoch, device)
);
CREATE TABLE IF NOT EXISTS records (
	chain    bytea NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
	id       bytea NOT NULL,
	version  bigint NOT NULL,
	epoch    integer NOT NULL,
	deleted  boolean NOT NULL,
	body     bytea NOT NULL,
	updated  timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (chain, id)
);
CREATE INDEX IF NOT EXISTS records_version ON records (chain, version);
CREATE INDEX IF NOT EXISTS records_tombstones ON records (updated) WHERE deleted;
CREATE TABLE IF NOT EXISTS blobs (
	chain    bytea NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
	id       bytea NOT NULL,
	data     bytea NOT NULL,
	created  timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (chain, id)
);
CREATE TABLE IF NOT EXISTS record_blobs (
	chain    bytea NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
	record   bytea NOT NULL,
	blob     bytea NOT NULL,
	PRIMARY KEY (chain, record, blob)
);
CREATE INDEX IF NOT EXISTS record_blobs_blob ON record_blobs (chain, blob);
CREATE TABLE IF NOT EXISTS forwards (
	chain    bytea NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
	device   bytea NOT NULL,
	envelope bytea NOT NULL,
	PRIMARY KEY (chain, device)
);
CREATE TABLE IF NOT EXISTS signatures (
	hash     bytea PRIMARY KEY,
	expires  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS signatures_expires ON signatures (expires);
CREATE TABLE IF NOT EXISTS pair_slots (
	id        text PRIMARY KEY,
	chain     bytea NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
	a_msg     bytea NOT NULL,
	b_msg     bytea,
	confirm   bytea,
	b_box     bytea,
	approval  bytea,
	created   timestamptz NOT NULL DEFAULT now()
);
`

// Migrate creates or updates the tables. Running it twice is harmless.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, schema)
	return err
}

// Ping checks the database.
func (s *Store) Ping(ctx context.Context) error { return s.Pool.Ping(ctx) }

// Chain is a chain's row.
type Chain struct {
	ID        []byte
	AuthKey   []byte
	Version   int64
	Bytes     int64
	Records   int64
	Horizon   int64
	Epoch     int
	Forwarded bool
}

// Device is a device's row.
type Device struct {
	ID, Sign, X25519, MLKEM, Name []byte
	Added                         time.Time
	Removed                       *time.Time
}

// Chain returns a chain.
func (s *Store) Chain(ctx context.Context, id []byte) (Chain, error) {
	var c Chain
	var fwd *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT id, auth_key, version, bytes, records, horizon, epoch, forwarded FROM chains WHERE id = $1`, id).
		Scan(&c.ID, &c.AuthKey, &c.Version, &c.Bytes, &c.Records, &c.Horizon, &c.Epoch, &fwd)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNoChain
	}
	c.Forwarded = fwd != nil
	return c, err
}

// Device returns a device of a chain.
func (s *Store) Device(ctx context.Context, chain, id []byte) (Device, error) {
	var d Device
	err := s.Pool.QueryRow(ctx, `SELECT id, sign, x25519, mlkem, name, added, removed FROM devices WHERE chain = $1 AND id = $2`, chain, id).
		Scan(&d.ID, &d.Sign, &d.X25519, &d.MLKEM, &d.Name, &d.Added, &d.Removed)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNoDevice
	}
	return d, err
}

// Devices lists a chain's devices.
func (s *Store) Devices(ctx context.Context, chain []byte) ([]Device, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, sign, x25519, mlkem, name, added, removed FROM devices WHERE chain = $1 ORDER BY added`, chain)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Device, error) {
		var d Device
		err := r.Scan(&d.ID, &d.Sign, &d.X25519, &d.MLKEM, &d.Name, &d.Added, &d.Removed)
		return d, err
	})
}

// UseSignature records a request signature; false if it was used before.
func (s *Store) UseSignature(ctx context.Context, hash []byte, expires time.Time) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO signatures (hash, expires) VALUES ($1, $2) ON CONFLICT DO NOTHING`, hash, expires)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// CreateChain stores a new chain with its first device and keyring.
func (s *Store) CreateChain(ctx context.Context, id, authKey []byte, d Device, wrapped, envelope []byte) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO chains (id, auth_key) VALUES ($1, $2)`, id, authKey); err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23505" {
				return ErrChainExists
			}
			return err
		}
		if err := insertDevice(ctx, tx, id, d); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO keyrings (chain, epoch, wrapped) VALUES ($1, 1, $2)`, id, wrapped); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO envelopes (chain, epoch, device, envelope) VALUES ($1, 1, $2, $3)`, id, d.ID, envelope)
		return err
	})
}

func insertDevice(ctx context.Context, tx pgx.Tx, chain []byte, d Device) error {
	_, err := tx.Exec(ctx, `INSERT INTO devices (chain, id, sign, x25519, mlkem, name) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (chain, id) DO UPDATE SET x25519 = excluded.x25519, mlkem = excluded.mlkem, name = excluded.name
		WHERE devices.removed IS NULL`, chain, d.ID, d.Sign, d.X25519, d.MLKEM, d.Name)
	return err
}

// AddDevice adds a device, with its envelope for the current epoch if given.
// A removed device cannot come back under the same key.
func (s *Store) AddDevice(ctx context.Context, chain []byte, d Device, envelope []byte) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var epoch int
		var fwd *time.Time
		if err := tx.QueryRow(ctx, `SELECT epoch, forwarded FROM chains WHERE id = $1 FOR UPDATE`, chain).Scan(&epoch, &fwd); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoChain
			}
			return err
		}
		if fwd != nil {
			return ErrForwarded
		}
		var removed *time.Time
		err := tx.QueryRow(ctx, `SELECT removed FROM devices WHERE chain = $1 AND id = $2`, chain, d.ID).Scan(&removed)
		if err == nil && removed != nil {
			return ErrNoDevice
		}
		if err := insertDevice(ctx, tx, chain, d); err != nil {
			return err
		}
		if envelope != nil {
			_, err := tx.Exec(ctx, `INSERT INTO envelopes (chain, epoch, device, envelope) VALUES ($1, $2, $3, $4)
				ON CONFLICT (chain, epoch, device) DO UPDATE SET envelope = excluded.envelope`, chain, epoch, d.ID, envelope)
			return err
		}
		return nil
	})
}

// RemoveDevice marks a device removed.
func (s *Store) RemoveDevice(ctx context.Context, chain, id []byte) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE devices SET removed = now() WHERE chain = $1 AND id = $2 AND removed IS NULL`, chain, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoDevice
	}
	_, err = s.Pool.Exec(ctx, `DELETE FROM envelopes WHERE chain = $1 AND device = $2`, chain, id)
	return err
}

// Keyring returns the current epoch, its wrapped key and the envelope of a device.
func (s *Store) Keyring(ctx context.Context, chain, device []byte) (epoch int, wrapped, envelope []byte, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT c.epoch, k.wrapped FROM chains c JOIN keyrings k ON k.chain = c.id AND k.epoch = c.epoch WHERE c.id = $1`, chain).Scan(&epoch, &wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, nil, ErrNoChain
	}
	if err != nil {
		return
	}
	err = s.Pool.QueryRow(ctx, `SELECT envelope FROM envelopes WHERE chain = $1 AND epoch = $2 AND device = $3`, chain, epoch, device).Scan(&envelope)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return
}

// Envelope is a sealed payload for one device.
type Envelope struct {
	Device, Envelope []byte
}

// NewEpoch starts the next epoch.
func (s *Store) NewEpoch(ctx context.Context, chain []byte, epoch int, wrapped []byte, envs []Envelope) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var cur int
		if err := tx.QueryRow(ctx, `SELECT epoch FROM chains WHERE id = $1 FOR UPDATE`, chain).Scan(&cur); err != nil {
			return err
		}
		if epoch != cur+1 {
			return ErrEpoch
		}
		if _, err := tx.Exec(ctx, `INSERT INTO keyrings (chain, epoch, wrapped) VALUES ($1, $2, $3)`, chain, epoch, wrapped); err != nil {
			return err
		}
		for _, e := range envs {
			if _, err := tx.Exec(ctx, `INSERT INTO envelopes (chain, epoch, device, envelope)
				SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM devices WHERE chain = $1 AND id = $3 AND removed IS NULL)`,
				chain, epoch, e.Device, e.Envelope); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE chains SET epoch = $2 WHERE id = $1`, chain, epoch)
		return err
	})
}

// Record is a stored record.
type Record struct {
	ID      []byte
	Version int64
	Epoch   int
	Deleted bool
	Body    []byte
}

// Write is one record of a batch.
type Write struct {
	ID        []byte
	Epoch     int
	Deleted   bool
	Body      []byte
	Blobs     [][]byte
	IfVersion *int64
}

// WriteRecords applies a batch atomically and returns the new versions.
func (s *Store) WriteRecords(ctx context.Context, chain []byte, writes []Write, lim Limits) ([]int64, error) {
	versions := make([]int64, len(writes))
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var c Chain
		var fwd *time.Time
		if err := tx.QueryRow(ctx, `SELECT version, bytes, records, epoch, forwarded FROM chains WHERE id = $1 FOR UPDATE`, chain).
			Scan(&c.Version, &c.Bytes, &c.Records, &c.Epoch, &fwd); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoChain
			}
			return err
		}
		if fwd != nil {
			return ErrForwarded
		}
		var conflicts [][]byte
		for i, w := range writes {
			if w.Epoch < 1 || w.Epoch > c.Epoch {
				return ErrEpoch
			}
			var curVersion int64
			var curSize int
			err := tx.QueryRow(ctx, `SELECT version, length(body) FROM records WHERE chain = $1 AND id = $2`, chain, w.ID).Scan(&curVersion, &curSize)
			exists := err == nil
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if w.IfVersion != nil && *w.IfVersion != curVersion {
				conflicts = append(conflicts, w.ID)
				continue
			}
			c.Version++
			versions[i] = c.Version
			c.Bytes += int64(len(w.Body) - curSize)
			if !exists {
				c.Records++
			}
			if _, err := tx.Exec(ctx, `INSERT INTO records (chain, id, version, epoch, deleted, body, updated) VALUES ($1, $2, $3, $4, $5, $6, now())
				ON CONFLICT (chain, id) DO UPDATE SET version = excluded.version, epoch = excluded.epoch, deleted = excluded.deleted, body = excluded.body, updated = now()`,
				chain, w.ID, c.Version, w.Epoch, w.Deleted, w.Body); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM record_blobs WHERE chain = $1 AND record = $2`, chain, w.ID); err != nil {
				return err
			}
			if w.Deleted {
				continue
			}
			for _, b := range w.Blobs {
				tag, err := tx.Exec(ctx, `INSERT INTO record_blobs (chain, record, blob)
					SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM blobs WHERE chain = $1 AND id = $3) ON CONFLICT DO NOTHING`, chain, w.ID, b)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					var n int
					if err := tx.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE chain = $1 AND id = $2`, chain, b).Scan(&n); err != nil {
						return err
					}
					if n == 0 {
						return ErrMissingBlob
					}
				}
			}
		}
		if len(conflicts) > 0 {
			return &ConflictError{IDs: conflicts}
		}
		if (lim.MaxBytes > 0 && c.Bytes > lim.MaxBytes) || (lim.MaxRecords > 0 && c.Records > lim.MaxRecords) {
			return ErrLimit
		}
		_, err := tx.Exec(ctx, `UPDATE chains SET version = $2, bytes = $3, records = $4 WHERE id = $1`, chain, c.Version, c.Bytes, c.Records)
		return err
	})
	if err != nil {
		return nil, err
	}
	return versions, nil
}

// Changes returns up to limit records with a version above since, and
// whether more follow.
func (s *Store) Changes(ctx context.Context, chain []byte, since int64, limit int) (int64, []Record, bool, error) {
	c, err := s.Chain(ctx, chain)
	if err != nil {
		return 0, nil, false, err
	}
	if c.Forwarded {
		return 0, nil, false, ErrForwarded
	}
	if since > 0 && since < c.Horizon {
		return 0, nil, false, ErrResync
	}
	rows, err := s.Pool.Query(ctx, `SELECT id, version, epoch, deleted, body FROM records WHERE chain = $1 AND version > $2 ORDER BY version LIMIT $3`, chain, since, limit+1)
	if err != nil {
		return 0, nil, false, err
	}
	recs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Record, error) {
		var x Record
		err := r.Scan(&x.ID, &x.Version, &x.Epoch, &x.Deleted, &x.Body)
		return x, err
	})
	if err != nil {
		return 0, nil, false, err
	}
	more := len(recs) > limit
	if more {
		recs = recs[:limit]
	}
	return c.Version, recs, more, nil
}

// PutBlob stores a blob once; storing the same ID again is a no-op.
func (s *Store) PutBlob(ctx context.Context, chain, id, data []byte, lim Limits) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var bytes int64
		var fwd *time.Time
		if err := tx.QueryRow(ctx, `SELECT bytes, forwarded FROM chains WHERE id = $1 FOR UPDATE`, chain).Scan(&bytes, &fwd); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoChain
			}
			return err
		}
		if fwd != nil {
			return ErrForwarded
		}
		tag, err := tx.Exec(ctx, `INSERT INTO blobs (chain, id, data) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, chain, id, data)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		bytes += int64(len(data))
		if lim.MaxBytes > 0 && bytes > lim.MaxBytes {
			return ErrLimit
		}
		_, err = tx.Exec(ctx, `UPDATE chains SET bytes = $2 WHERE id = $1`, chain, bytes)
		return err
	})
}

// Blob returns a blob.
func (s *Store) Blob(ctx context.Context, chain, id []byte) ([]byte, bool, error) {
	var data []byte
	err := s.Pool.QueryRow(ctx, `SELECT data FROM blobs WHERE chain = $1 AND id = $2`, chain, id).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	return data, err == nil, err
}

// Forward wipes a chain's data and keeps the forwarding envelopes.
func (s *Store) Forward(ctx context.Context, chain []byte, envs []Envelope) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE chains SET forwarded = now(), bytes = 0, records = 0 WHERE id = $1 AND forwarded IS NULL`, chain)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrForwarded
		}
		for _, q := range []string{
			`DELETE FROM record_blobs WHERE chain = $1`, `DELETE FROM records WHERE chain = $1`,
			`DELETE FROM blobs WHERE chain = $1`, `DELETE FROM envelopes WHERE chain = $1`,
			`DELETE FROM keyrings WHERE chain = $1`, `DELETE FROM pair_slots WHERE chain = $1`,
		} {
			if _, err := tx.Exec(ctx, q, chain); err != nil {
				return err
			}
		}
		for _, e := range envs {
			if _, err := tx.Exec(ctx, `INSERT INTO forwards (chain, device, envelope)
				SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM devices WHERE chain = $1 AND id = $2 AND removed IS NULL)`,
				chain, e.Device, e.Envelope); err != nil {
				return err
			}
		}
		return nil
	})
}

// ForwardEnvelope returns a device's forwarding envelope.
func (s *Store) ForwardEnvelope(ctx context.Context, chain, device []byte) ([]byte, error) {
	var env []byte
	err := s.Pool.QueryRow(ctx, `SELECT envelope FROM forwards WHERE chain = $1 AND device = $2`, chain, device).Scan(&env)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoDevice
	}
	return env, err
}

func interval(d time.Duration) string { return fmt.Sprintf("%d milliseconds", d.Milliseconds()) }

// Retention is how long the cleaner keeps things.
type Retention struct {
	Tombstones time.Duration
	BlobGrace  time.Duration
	Forwards   time.Duration
	PairSlots  time.Duration
}

// Clean compacts tombstones, collects unused blobs, drops expired forwards,
// pairing slots and signatures. It returns how many rows each step removed.
func (s *Store) Clean(ctx context.Context, r Retention) (map[string]int64, error) {
	out := map[string]int64{}
	steps := []struct {
		name string
		sql  string
		arg  any
	}{
		{"horizon", `UPDATE chains c SET horizon = GREATEST(c.horizon, t.v) FROM (
			SELECT chain, max(version) AS v FROM records WHERE deleted AND updated < now() - $1::interval GROUP BY chain) t
			WHERE c.id = t.chain`, r.Tombstones},
		{"tombstones", `WITH gone AS (DELETE FROM records WHERE deleted AND updated < now() - $1::interval RETURNING chain, length(body) AS n)
			UPDATE chains c SET records = c.records - g.cnt, bytes = c.bytes - g.sz FROM (
			SELECT chain, count(*) AS cnt, sum(n) AS sz FROM gone GROUP BY chain) g WHERE c.id = g.chain`, r.Tombstones},
		{"blobs", `WITH gone AS (DELETE FROM blobs b WHERE b.created < now() - $1::interval
			AND NOT EXISTS (SELECT 1 FROM record_blobs rb WHERE rb.chain = b.chain AND rb.blob = b.id) RETURNING chain, length(data) AS n)
			UPDATE chains c SET bytes = c.bytes - g.sz FROM (SELECT chain, sum(n) AS sz FROM gone GROUP BY chain) g WHERE c.id = g.chain`, r.BlobGrace},
		{"forwards", `DELETE FROM chains WHERE forwarded < now() - $1::interval`, r.Forwards},
		{"pair_slots", `DELETE FROM pair_slots WHERE created < now() - $1::interval`, r.PairSlots},
		{"signatures", `DELETE FROM signatures WHERE expires < now() - $1::interval`, time.Duration(0)},
	}
	for _, st := range steps {
		tag, err := s.Pool.Exec(ctx, st.sql, interval(st.arg.(time.Duration)))
		if err != nil {
			return out, fmt.Errorf("%s: %w", st.name, err)
		}
		out[st.name] = tag.RowsAffected()
	}
	return out, nil
}
