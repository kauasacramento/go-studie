package eventbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

type Store interface {
	Save(ctx context.Context, event Event) error
	Get(ctx context.Context, id string) (Event, error)
}

type Publisher interface {
	Publish(ctx context.Context, subject string, body []byte) error
}

type Service struct {
	store     Store
	publisher Publisher
	subject   string
}

func NewService(store Store, publisher Publisher, subject string) (*Service, error) {
	if store == nil {
		return nil, errors.New("store obrigatorio")
	}
	if publisher == nil {
		return nil, errors.New("publisher obrigatorio")
	}
	if subject == "" {
		return nil, errors.New("subject obrigatorio")
	}

	return &Service{store: store, publisher: publisher, subject: subject}, nil
}

func (s *Service) Handle(ctx context.Context, raw []byte) (Event, error) {
	event, err := DecodeEvent(raw)
	if err != nil {
		return Event{}, fmt.Errorf("decode event: %w", err)
	}

	if err := s.store.Save(ctx, event); err != nil {
		return Event{}, fmt.Errorf("save event: %w", err)
	}

	body, err := json.Marshal(event)
	if err != nil {
		return Event{}, fmt.Errorf("marshal event: %w", err)
	}

	if err := s.publisher.Publish(ctx, s.subject, body); err != nil {
		return Event{}, fmt.Errorf("publish event: %w", err)
	}

	return event, nil
}
