package mpc

import (
	"sync"

	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type Network struct {
	accept chan *protocol.Message
	send   chan<- *protocol.Message

	done chan struct{}
	mtx  sync.Mutex
}

func NewNetwork() (*Network, chan<- *protocol.Message) {
	accept := make(chan *protocol.Message, 4)
	return &Network{
		accept: accept,
	}, accept
}

func (n *Network) Next() <-chan *protocol.Message {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	return n.accept
}

func (n *Network) Send(msg *protocol.Message) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	n.send <- msg
}

func (n *Network) Done() chan struct{} {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	close(n.done)
	return n.done
}

func (n *Network) SetSendCh(send chan<- *protocol.Message) {
	n.send = send
}
