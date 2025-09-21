package network

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type Communication interface {
	NewChannel(string) Channel
}

type Channel interface {
	Next() <-chan *protocol.Message
	Send(*protocol.Message)
	Done() chan struct{}
}

func HandlerLoop(id party.ID, h protocol.Handler, channel Channel) {
	for {
		select {
		case msg, ok := <-h.Listen():
			if !ok {
				channel.Done()
				return
			}
			channel.Send(msg)
		case msg := <-channel.Next():
			h.Accept(msg)
		}
	}
}
