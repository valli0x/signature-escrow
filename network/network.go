package network

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type Network interface {
	Next() <-chan *protocol.Message

	Send(*protocol.Message)

	Done() chan struct{}
}

func HandlerLoop(id party.ID, h protocol.Handler, network Network) {
	for {
		select {
		case msg, ok := <-h.Listen():
			if !ok {
				return
			}
			network.Send(msg)
		case msg := <-network.Next():
			h.Accept(msg)
		}
	}
}
