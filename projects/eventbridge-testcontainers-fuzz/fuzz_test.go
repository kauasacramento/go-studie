package eventbridge

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzDecodeEvent(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"id":"evt-1","user_id":"user-1","type":"order.created","payload":{"amount":10},"created_at":"2026-04-02T10:00:00Z"}`),
		[]byte(`{"id":"evt-2","user_id":"user-2","type":"ORDER.PAID","payload":{"amount":99},"created_at":"2026-04-02T10:00:00Z"}`),
		[]byte(`{}`),
		[]byte(`not-json`),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		event, err := DecodeEvent(data)
		if err != nil {
			return
		}

		if validateErr := event.Validate(); validateErr != nil {
			t.Fatalf("decoded event must remain valid: %v", validateErr)
		}
		if event.Type != strings.ToLower(event.Type) {
			t.Fatalf("expected lowercase type, got %q", event.Type)
		}
		if !json.Valid(event.Payload) {
			t.Fatalf("payload must remain valid json: %s", string(event.Payload))
		}
	})
}
