package ssh

import (
	"context"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh/handshake"
	log "github.com/sirupsen/logrus"
	"net"
)

type Server struct {
	priKey   []byte
	pubKey   []byte
	underlay tunnel.Server
	connChan chan tunnel.Conn
	ctx      context.Context
	cancel   context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("transport server closed")
	}
}
func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Fatal(common.NewError("transport accept error" + err.Error()))
			}
			return
		}
		go func(conn net.Conn) {
			tlsConn, err := handshake.Server(conn, &handshake.AuthInfo{
				PublicKey:  s.pubKey,
				PrivateKey: s.priKey,
			})
			if err != nil {
				log.Warnf("服务端处理握手失败%v", err)
				conn.Close()
				return
			}
			s.connChan <- &Conn{
				Conn: tlsConn,
			}
		}(conn)
	}
}
func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	pri, pub, err := handshake.LoadKeyPair(cfg.Ssh.Pri, cfg.Ssh.Pub)
	if err != nil {
		return nil, common.NewError("ssh failed to load key pair")
	}
	handshake.InitSeed()
	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		underlay: underlay,
		priKey:   pri,
		pubKey:   pub,
		connChan: make(chan tunnel.Conn, 32),
		ctx:      ctx,
		cancel:   cancel,
	}
	go server.acceptLoop()
	log.Debugf("ssh server created")
	return server, nil
}
