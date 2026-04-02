package eventbridge

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Save(ctx context.Context, event Event) error {
	_, err := s.pool.Exec(
		ctx,
		`insert into events (id, user_id, type, payload, created_at) values ($1, $2, $3, $4, $5)`,
		event.ID,
		event.UserID,
		event.Type,
		[]byte(event.Payload),
		event.CreatedAt.UTC(),
	)
	return err
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Event, error) {
	var event Event
	if err := s.pool.QueryRow(
		ctx,
		`select id, user_id, type, payload, created_at from events where id = $1`,
		id,
	).Scan(&event.ID, &event.UserID, &event.Type, &event.Payload, &event.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("query event: %w", err)
	}

	return event, nil
}
