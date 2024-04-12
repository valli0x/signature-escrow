package exchange

import (
	"context"
	"net"

	pb "github.com/valli0x/signature-escrow/network/server/proto"
	"google.golang.org/grpc"
)

type server struct {
	port string
	pb.UnimplementedExchangeServer
}

func NewServer(port string) *server {
	return &server{
		port: port,
	}
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
	// name := in.Name
	// msg := in.Msgbody

	return &pb.SendRes{}, nil
}

func (s *server) Next(req *pb.NextReq, stream pb.Exchange_NextServer) error {

	return nil
}
