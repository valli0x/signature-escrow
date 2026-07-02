package network

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	pb "github.com/valli0x/signature-escrow/network/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

const relayStreamName = "RELAY"

type server struct {
	port, natsurl string
	nc            *nats.Conn
	js            nats.JetStreamContext
	pb.UnimplementedExchangeServer
}

func NewServer(port string, natsurl string) (*server, error) {
	nc, err := nats.Connect(natsurl,
		nats.Timeout(10*time.Second),
		nats.ReconnectWait(2*time.Second),
		nats.MaxReconnects(-1),

		nats.PingInterval(30*time.Second),
		nats.MaxPingsOutstanding(3),

		nats.ReconnectBufSize(16<<20),

		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			slog.Info("NATS error", "error", err)
		}),

		nats.ReconnectHandler(func(nc *nats.Conn) {
			slog.Info("NATS reconnected", "url", nc.ConnectedUrl())
		}),

		nats.DisconnectHandler(func(nc *nats.Conn) {
			slog.Info("NATS disconnected")
		}),
	)
	if err != nil {
		slog.Error("NATS connection error", "error", err)
		return nil, err
	}

	js, err := nc.JetStream()
	if err != nil {
		slog.Error("JetStream init error", "error", err)
		return nil, err
	}

	cfg := &nats.StreamConfig{
		Name:      relayStreamName,
		Subjects:  []string{"*"},
		Retention: nats.WorkQueuePolicy,
		Storage:   nats.MemoryStorage,
		Discard:   nats.DiscardOld,
		MaxAge:    10 * time.Minute,
	}
	if _, err := js.AddStream(cfg); err != nil {
		if _, uerr := js.UpdateStream(cfg); uerr != nil {
			slog.Warn("relay stream setup (continuing)", "add_err", err, "update_err", uerr)
		}
	}

	return &server{
		port:    port,
		natsurl: natsurl,
		nc:      nc,
		js:      js,
	}, nil
}

func (s *server) Run() error {
	lis, err := net.Listen("tcp", s.port)
	if err != nil {
		return err
	}

	grpcserver := grpc.NewServer(
		grpc.MaxRecvMsgSize(16<<20),
		grpc.MaxSendMsgSize(16<<20),

		grpc.MaxConcurrentStreams(1000),
		grpc.NumStreamWorkers(uint32(runtime.NumCPU())),

		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	pb.RegisterExchangeServer(grpcserver, s)

	if err := grpcserver.Serve(lis); err != nil {
		return err
	}
	return nil
}

func (s *server) Send(ctx context.Context, in *pb.SendReq) (*pb.SendRes, error) {
	if _, err := s.js.Publish(in.Name, []byte(in.Msgbody)); err != nil {
		return &pb.SendRes{}, err
	}
	return &pb.SendRes{}, nil
}

func (s *server) Next(req *pb.NextReq, stream pb.Exchange_NextServer) error {
	invalidName := strings.Contains(req.Name, "*") || strings.Contains(req.Name, ">")
	if req.Name == "" || invalidName {
		return errors.New("invalid name")
	}

	sub, err := s.js.Subscribe(req.Name, func(m *nats.Msg) {
		if err := stream.Send(&pb.NextRes{
			Msgbody: string(m.Data),
		}); err != nil {
			fmt.Println("error with nats message handling", err)
			return
		}
		_ = m.Ack()
	},
		nats.DeliverAll(),
		nats.AckExplicit(),
		nats.ManualAck(),
	)
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()

	<-stream.Context().Done()
	return nil
}
