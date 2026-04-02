package eventbridge

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestServiceIntegration_PostgresAndNATS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pgContainer, err := postgres.Run(
		ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("events_db"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
	)
	if shouldSkipDocker(err) {
		t.Skipf("skipping integration test: %v", err)
	}
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		_ = pgContainer.Terminate(context.Background())
	})

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}
	dsn = strings.Replace(dsn, "localhost", "127.0.0.1", 1)

	pool, err := newReadyPostgresPool(ctx, dsn)
	if err != nil {
		t.Fatalf("create pgx pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := execWithRetry(ctx, 20, 500*time.Millisecond, func() error {
		_, err := pool.Exec(ctx, `
		create table if not exists events (
			id text primary key,
			user_id text not null,
			type text not null,
			payload jsonb not null,
			created_at timestamptz not null
		)
	`)
		return err
	}); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	natsContainer, natsURL, err := startNATSContainer(ctx)
	if shouldSkipDocker(err) {
		t.Skipf("skipping integration test: %v", err)
	}
	if err != nil {
		t.Fatalf("start nats container: %v", err)
	}
	t.Cleanup(func() {
		_ = natsContainer.Terminate(context.Background())
	})

	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	t.Cleanup(nc.Close)

	sub, err := nc.SubscribeSync("events.ingested")
	if err != nil {
		t.Fatalf("subscribe nats: %v", err)
	}
	if err := nc.FlushTimeout(5 * time.Second); err != nil {
		t.Fatalf("flush nats subscription: %v", err)
	}

	service, err := NewService(NewPostgresStore(pool), NewNATSPublisher(nc), "events.ingested")
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	raw := []byte(`{"id":"evt-int-1","user_id":"user-99","type":"ORDER.CREATED","payload":{"amount":250,"currency":"BRL"},"created_at":"2026-04-02T10:00:00Z"}`)

	handled, err := service.Handle(ctx, raw)
	if err != nil {
		t.Fatalf("handle event: %v", err)
	}

	stored, err := NewPostgresStore(pool).Get(ctx, handled.ID)
	if err != nil {
		t.Fatalf("load stored event: %v", err)
	}
	if stored.ID != handled.ID || stored.Type != "order.created" {
		t.Fatalf("unexpected stored event: %+v", stored)
	}

	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("receive nats message: %v", err)
	}

	received, err := DecodeEvent(msg.Data)
	if err != nil {
		t.Fatalf("decode published message: %v", err)
	}
	if received.ID != handled.ID || received.UserID != handled.UserID {
		t.Fatalf("unexpected published event: %+v", received)
	}
}

func startNATSContainer(ctx context.Context) (testcontainers.Container, string, error) {
	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "nats:2.10-alpine",
				ExposedPorts: []string{"4222/tcp"},
				WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(60 * time.Second),
			},
			Started: true,
		},
	)
	if err != nil {
		return nil, "", err
	}

	host, err := container.Host(ctx)
	if err != nil {
		return nil, "", err
	}
	port, err := container.MappedPort(ctx, "4222/tcp")
	if err != nil {
		return nil, "", err
	}

	return container, fmt.Sprintf("nats://%s:%s", host, port.Port()), nil
}

func shouldSkipDocker(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	markers := []string{
		"docker",
		"daemon",
		"provider not found",
		"connectex",
		"cannot connect",
		"no such file or directory",
	}

	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}

	return false
}

func newReadyPostgresPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}

	if err := execWithRetry(ctx, 30, 500*time.Millisecond, func() error {
		return pool.Ping(ctx)
	}); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

func execWithRetry(ctx context.Context, attempts int, interval time.Duration, fn func() error) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return fmt.Errorf("context done after retries: %w (last error: %v)", err, lastErr)
			}
			return err
		}

		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("context done after retries: %w (last error: %v)", ctx.Err(), lastErr)
			}
			return ctx.Err()
		case <-time.After(interval):
		}
	}

	return fmt.Errorf("all retries failed: %w", lastErr)
}
