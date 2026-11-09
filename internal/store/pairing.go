package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PairSlot relays one pairing (§8): A's SPAKE2 message, B's message,
// confirmation and sealed device info, and A's sealed approval.
type PairSlot struct {
	ID       string
	Chain    []byte
	AMsg     []byte
	BMsg     []byte
	Confirm  []byte
	BBox     []byte
	Approval []byte
	Created  time.Time
}

// CreatePairSlot opens a slot. Expired slots with the same ID are replaced.
func (s *Store) CreatePairSlot(ctx context.Context, slot PairSlot, ttl time.Duration) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM pair_slots WHERE id = $1 AND created < now() - $2::interval`, slot.ID, interval(ttl)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO pair_slots (id, chain, a_msg) VALUES ($1, $2, $3)`, slot.ID, slot.Chain, slot.AMsg)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return ErrSlotTaken
		}
		return err
	})
}

// PairSlot returns a live slot.
func (s *Store) PairSlot(ctx context.Context, id string, ttl time.Duration) (PairSlot, error) {
	var p PairSlot
	err := s.Pool.QueryRow(ctx, `SELECT id, chain, a_msg, b_msg, confirm, b_box, approval, created FROM pair_slots
		WHERE id = $1 AND created >= now() - $2::interval`, id, interval(ttl)).
		Scan(&p.ID, &p.Chain, &p.AMsg, &p.BMsg, &p.Confirm, &p.BBox, &p.Approval, &p.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNoSlot
	}
	return p, err
}

// JoinPairSlot records B's answer, once.
func (s *Store) JoinPairSlot(ctx context.Context, id string, msg, confirm, box []byte, ttl time.Duration) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE pair_slots SET b_msg = $2, confirm = $3, b_box = $4
		WHERE id = $1 AND b_msg IS NULL AND created >= now() - $5::interval`, id, msg, confirm, box, interval(ttl))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return s.slotState(ctx, id, ttl)
	}
	return nil
}

// ApprovePairSlot records A's approval, once, after B joined.
func (s *Store) ApprovePairSlot(ctx context.Context, id string, chain, box []byte, ttl time.Duration) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE pair_slots SET approval = $3
		WHERE id = $1 AND chain = $2 AND b_msg IS NOT NULL AND approval IS NULL AND created >= now() - $4::interval`, id, chain, box, interval(ttl))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return s.slotState(ctx, id, ttl)
	}
	return nil
}

// DeletePairSlot removes a slot of the chain.
func (s *Store) DeletePairSlot(ctx context.Context, id string, chain []byte) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM pair_slots WHERE id = $1 AND chain = $2`, id, chain)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSlot
	}
	return nil
}

func (s *Store) slotState(ctx context.Context, id string, ttl time.Duration) error {
	if _, err := s.PairSlot(ctx, id, ttl); err != nil {
		return err
	}
	return ErrSlotUsed
}
