package redis

import (
	"context"
	"encoding/base64"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/redis/go-redis/v9"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network"
)

type RedisNet struct {
	client       *redis.Client
	accept, send string
	done         chan struct{}
	out          chan *protocol.Message
	logger       hclog.Logger
	mtx          sync.Mutex
}

func NewRedisNet(addr, accept, send string, logger hclog.Logger) (network.Network, error) {
	r := &RedisNet{
		accept: accept,
		send:   send,
		client: redis.NewClient(&redis.Options{
			Addr: addr,
		}),
		logger: logger,
		out:    make(chan *protocol.Message, 4),
		done:   make(chan struct{}),
	}
	go r.receiving()
	return r, nil
}

func (r *RedisNet) receiving() {
	pubsub := r.client.Subscribe(context.Background(), r.accept)
	defer pubsub.Close()

	for m := range pubsub.Channel() {
		select {
		case <-r.done:
			return
		default:
		}

		data, err := base64.StdEncoding.DecodeString(m.Payload)
		if err != nil {
			r.logger.Error("base64 unmarshal error", err)
			continue
		}

		msg := &protocol.Message{}
		if err := msg.UnmarshalBinary(data); err != nil {
			r.logger.Error("message unmarchal error", err)
			continue
		}
		r.out <- msg
	}
}

func (r *RedisNet) Next() <-chan *protocol.Message {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	return r.out
}

func (r *RedisNet) Send(msg *protocol.Message) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	data, err := msg.MarshalBinary()
	if err != nil {
		r.logger.Error("marchal binary error", err)
		return
	}
	dataStr := base64.StdEncoding.EncodeToString(data)

	if err = r.client.Publish(context.Background(), r.send, dataStr).Err(); err != nil {
		r.logger.Error("publish error", err)
	}
}

func (r *RedisNet) Done() chan struct{} {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	close(r.done)
	return r.done
}

