package eventbridge

import (
	"strings"
	"testing"
)

func TestNormalizeTopic(t *testing.T) {
	topic, err := NormalizeTopic("  ORDER.CREATED  ")
	if err != nil {
		t.Fatalf("NormalizeTopic returned error: %v", err)
	}
	if topic != "order.created" {
		t.Fatalf("expected normalized topic, got %q", topic)
	}
}

func TestDecodeEvent(t *testing.T) {
	raw := []byte(`{"id":"evt-1","user_id":"user-1","type":"ORDER.PAID","payload":{"amount":42},"created_at":"2026-04-02T10:00:00Z"}`)

	event, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent returned error: %v", err)
	}
	if event.Type != "order.paid" {
		t.Fatalf("expected normalized type, got %q", event.Type)
	}
	if string(event.Payload) != `{"amount":42}` {
		t.Fatalf("unexpected payload: %s", string(event.Payload))
	}
}

func TestDecodeEventRejectsUnknownType(t *testing.T) {
	raw := []byte(`{"id":"evt-1","user_id":"user-1","type":"invoice.sent","payload":{"amount":42},"created_at":"2026-04-02T10:00:00Z"}`)

	_, err := DecodeEvent(raw)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if !strings.Contains(err.Error(), "tipo nao suportado") {
		t.Fatalf("unexpected error: %v", err)
	}
}
