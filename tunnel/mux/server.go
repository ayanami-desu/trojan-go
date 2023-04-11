package mux

import (
	"context"
	"errors"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/sagernet/smux"
	log "github.com/sirupsen/logrus"
	"io"
)

// Server is a smux server
type Server struct {
	underlay tunnel.Server
	connChan chan tunnel.Conn
	ctx      context.Context
	cancel   context.CancelFunc
}

func (s *Server) acceptConnWorker() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			log.Debug(err)
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			smuxConfig := smux.DefaultConfig()
			smuxConfig.KeepAliveDisabled = true
			smuxSession, err := smux.Server(conn, smuxConfig)
			if err != nil {
				log.Error(err)
				return
			}
			go func(session *smux.Session, conn tunnel.Conn) {
				defer session.Close()
				for {
					stream, err := session.AcceptStream()
					if err != nil {
						if errors.Is(err, io.EOF) {
							log.Info(err)
						} else {
							log.Error(err)
						}
						return
					}
					//buf := make([]byte, 8)
					//stream.SetReadDeadline(time.Now().Add(time.Second))
					//_, err = io.ReadFull(stream, buf)
					//if err != nil {
					//	stream.Close()
					//	log.Errorf("broken stream")
					//	continue
					//}
					//stream.SetReadDeadline(time.Time{})
					select {
					case s.connChan <- &Conn{
						rwc:  stream,
						Conn: conn,
						//buf:  buf,
					}:
					case <-s.ctx.Done():
						log.Debug("exiting")
						return
					}
				}
			}(smuxSession, conn)
		}(conn)
	}
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("mux server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		underlay: underlay,
		ctx:      ctx,
		cancel:   cancel,
		connChan: make(chan tunnel.Conn, 32),
	}
	go server.acceptConnWorker()
	log.Debug("mux server created")
	return server, nil
}
