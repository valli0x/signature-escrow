package network

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

// Network - describing network method for cmp
type Network interface {
	// get message for participant
	Next(party.ID) <-chan *protocol.Message

	// send message for other participant
	Send(*protocol.Message)

	// close network
	Done(party.ID) chan struct{}

	// remove participant from our list participants
	Quit(party.ID)
}

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network Network) {
	for {
		select {
		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			// fmt.Println("send msg", msg)
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			// fmt.Println("accept msg", msg)
			h.Accept(msg)
		}
	}
}
