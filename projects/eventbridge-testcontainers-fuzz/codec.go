package eventbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maxPayloadSize = 4096

var allowedTypes = map[string]struct{}{
	"order.created":   {},
	"order.paid":      {},
	"order.cancelled": {},
	"user.blocked":    {},
}

type Event struct {
	ID        string          `json:"id"`
	UserID    string          `json:"user_id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}

func DecodeEvent(data []byte) (Event, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Event{}, errors.New("payload vazio")
	}
	if len(trimmed) > maxPayloadSize {
		return Event{}, fmt.Errorf("payload excede %d bytes", maxPayloadSize)
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()

	var event Event
	if err := decoder.Decode(&event); err != nil {
		return Event{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Event{}, errors.New("json com dados extras")
	}

	normalized, err := NormalizeTopic(event.Type)
	if err != nil {
		return Event{}, err
	}
	event.Type = normalized

	if err := event.Validate(); err != nil {
		return Event{}, err
	}

	return event, nil
}

func NormalizeTopic(input string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(input))
	if normalized == "" {
		return "", errors.New("topic obrigatorio")
	}
	if len(normalized) > 64 {
		return "", errors.New("topic muito grande")
	}

	for _, r := range normalized {
		isLetter := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		isAllowedSymbol := r == '.' || r == '-' || r == '_'
		if !isLetter && !isDigit && !isAllowedSymbol {
			return "", fmt.Errorf("topic invalido: %q", normalized)
		}
	}

	return normalized, nil
}

func (e Event) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return errors.New("id obrigatorio")
	}
	if strings.TrimSpace(e.UserID) == "" {
		return errors.New("user_id obrigatorio")
	}
	if e.CreatedAt.IsZero() {
		return errors.New("created_at obrigatorio")
	}
	if len(e.Payload) == 0 {
		return errors.New("payload obrigatorio")
	}
	if len(e.Payload) > maxPayloadSize {
		return fmt.Errorf("payload excede %d bytes", maxPayloadSize)
	}
	if !json.Valid(e.Payload) {
		return errors.New("payload json invalido")
	}
	if _, ok := allowedTypes[e.Type]; !ok {
		return fmt.Errorf("tipo nao suportado: %s", e.Type)
	}

	return nil
}
