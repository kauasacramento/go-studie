package eventbridge

import (
	"context"

	"github.com/nats-io/nats.go"
)

type NATSPublisher struct {
	conn *nats.Conn
}

func NewNATSPublisher(conn *nats.Conn) *NATSPublisher {
	return &NATSPublisher{conn: conn}
}

func (p *NATSPublisher) Publish(ctx context.Context, subject string, body []byte) error {
	msg := nats.NewMsg(subject)
	msg.Data = body

	if err := p.conn.PublishMsg(msg); err != nil {
		return err
	}

	return p.conn.FlushWithContext(ctx)
}
