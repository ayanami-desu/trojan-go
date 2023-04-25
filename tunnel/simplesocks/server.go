package simplesocks

import (
	"context"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/http2"
	"github.com/p4gefau1t/trojan-go/tunnel/singmux"
	log "github.com/sirupsen/logrus"
)

// Server is a simplesocks server
type Server struct {
	underlay     tunnel.Server
	readMetadata bool
	connChan     chan tunnel.Conn
	packetChan   chan tunnel.PacketConn
	ctx          context.Context
	cancel       context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			log.Errorf(common.NewError("simplesocks failed to accept connection from underlying tunnel").Base(err).Error())
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			metadata := new(tunnel.Metadata)
			if s.readMetadata {
				if err := metadata.ReadFrom(conn); err != nil {
					log.Errorf(common.NewError("simplesocks server faield to read header").Base(err).Error())
					conn.Close()
					return
				}
			} else {
				metadata = conn.Metadata()
			}
			switch metadata.Command {
			case Connect:
				s.connChan <- &Conn{
					metadata: metadata,
					Conn:     conn,
				}
			case Associate:
				s.packetChan <- &PacketConn{
					Conn: conn,
				}
			default:
				log.Errorf("simplesocks unknown command %d", metadata.Command)
				conn.Close()
			}
		}(conn)
	}
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("simplesocks server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case packetConn := <-s.packetChan:
		return packetConn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("simplesocks server closed")
	}
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	ctx, cancel := context.WithCancel(ctx)
	_, ok1 := underlay.(*http2.Server)
	_, ok2 := underlay.(*singmux.Server)
	ok := ok1 || ok2
	server := &Server{
		underlay:     underlay,
		readMetadata: !ok,
		ctx:          ctx,
		connChan:     make(chan tunnel.Conn, 32),
		packetChan:   make(chan tunnel.PacketConn, 32),
		cancel:       cancel,
	}
	go server.acceptLoop()
	log.Debug("simplesocks server created")
	return server, nil
}
