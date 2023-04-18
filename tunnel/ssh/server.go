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
	underlay tunnel.Server
	hkFunc   handshake.HkFunc
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
		conn, err := s.underlay.AcceptConn(nil)
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Fatalf("ssh accept error, %v", err)
			}
			return
		}
		go func(conn net.Conn) {
			sshConn, err := s.hkFunc.HandleHandShake(conn)
			if err != nil {
				log.Warnf("server failed to handshake: %v", err)
				conn.Close()
				return
			}
			s.connChan <- &Conn{
				Conn: sshConn,
			}
		}(conn)
	}
}
func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	hk := handshake.Init(cfg.Ssh.Pri, cfg.Ssh.Pub, cfg.Ssh.Rtt)
	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		underlay: underlay,
		hkFunc:   hk,
		connChan: make(chan tunnel.Conn, 32),
		ctx:      ctx,
		cancel:   cancel,
	}
	go server.acceptLoop()
	log.Debug("ssh server created")
	return server, nil
}
