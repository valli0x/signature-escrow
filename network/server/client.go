package exchange

import (
	"context"
	"encoding/base64"
	"io"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	pb "github.com/valli0x/signature-escrow/network/server/proto"
	"google.golang.org/grpc"
)

type client struct {
	address      string
	accept, send string
	grpc         pb.ExchangeClient
	conn         *grpc.ClientConn
	out          chan *protocol.Message
	logger       hclog.Logger
	mtx          sync.Mutex
	done         chan struct{}
}

func NewClient(address, accept, send string, logger hclog.Logger) (*client, error) {
	conn, err := grpc.Dial(address)
	if err != nil {
		return nil, err
	}
	client := &client{
		address: address,
		grpc:    pb.NewExchangeClient(conn),
		conn:    conn,
		accept:  accept,
		send:    send,
		logger:  logger,
	}
	go client.receiving()
	return client, nil
}

func (c *client) receiving() {
	stream, err := c.grpc.Next(context.Background(), &pb.NextReq{Name: c.accept})
	if err != nil {
		c.logger.Error("could not start Next stream: %v", err)
	}

	for {
		nextRes, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.logger.Error("failed to receive a NextRes: %v", err)
			break
		}

		data, err := base64.StdEncoding.DecodeString(nextRes.GetMsgbody())
		if err != nil {
			c.logger.Error("base64 unmarshal error", err)
			break
		}

		msg := &protocol.Message{}
		if err := msg.UnmarshalBinary(data); err != nil {
			c.logger.Error("message unmarchal error", err)
			break
		}

		c.out <- msg
	}
}

func (c *client) Send(msg *protocol.Message) {
	data, err := msg.MarshalBinary()
	if err != nil {
		c.logger.Error("marchal binary error", err)
		return
	}
	dataStr := base64.StdEncoding.EncodeToString(data)

	_, err = c.grpc.Send(context.Background(), &pb.SendReq{Name: c.send, Msgbody: dataStr})
	if err != nil {
		c.logger.Error("could not send: %v", err)
	}
}

func (c *client) Next() <-chan *protocol.Message {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.out
}

func (c *client) Done() chan struct{} {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.conn.Close()
	close(c.done)

	return c.done
}
