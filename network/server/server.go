package exchange

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	nats "github.com/nats-io/nats.go"
	pb "github.com/valli0x/signature-escrow/network/server/proto"
	"google.golang.org/grpc"
)

type server struct {
	port, natsurl string
	nc         *nats.Conn
	pb.UnimplementedExchangeServer
}

func NewServer(port string, natsurl string) (*server, error) {
	nc, err := nats.Connect(natsurl)
	if err != nil {
		log.Fatal(err)
	}
	return &server{
		port: port,
		natsurl: natsurl,
		nc:   nc,
	}, nil
}

func (s *server) Run() error {
	lis, err := net.Listen("tcp", s.port)
	if err != nil {
		return err
	}

	grpcserver := grpc.NewServer()
	pb.RegisterExchangeServer(grpcserver, s)

	if err := grpcserver.Serve(lis); err != nil {
		return err
	}
	return nil
}

func (s *server) Send(ctx context.Context, in *pb.SendReq) (*pb.SendRes, error) {
	if err := s.nc.Publish(in.Name, []byte(in.Msgbody)); err != nil {
		return &pb.SendRes{}, err
	}
	return &pb.SendRes{}, nil
}

func (s *server) Next(req *pb.NextReq, stream pb.Exchange_NextServer) error {
	invalidName := strings.Contains(req.Name, "*") || strings.Contains(req.Name, ">")
	if req.Name == "" || invalidName {
		return errors.New("invalid name")
	}

	msgHandler := func(m *nats.Msg) {
		if err := stream.Send(&pb.NextRes{
			Msgbody: string(m.Data),
		}); err != nil {
			fmt.Println("error with nats message handling", err)
		}
	}

	if _, err := s.nc.Subscribe(req.Name, msgHandler); err != nil {
		return err
	}
	return nil
}
