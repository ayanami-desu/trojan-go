package multiplex

import (
	"context"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	manage     *SessionManage
	sessConfig SessionConfig
	underlay   tunnel.Server
	connChan   chan tunnel.Conn
	ctx        context.Context
	cancel     context.CancelFunc
}

func (s *Server) acceptConnWorker() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			log.Warn(err)
			continue
		}
		sshConn, ok := conn.(*ssh.Conn)
		if !ok {
			log.Info("接收到的连接不是sshConn")
			continue
		}
		sessionId := transSessionId(sshConn.GetSessionId())
		sess, exist, err := s.manage.GetSession(sessionId, s.sessConfig)
		if err != nil {
			log.Warnf("获取会话失败，sessionId is: %v", sessionId)
			continue
		}
		sess.AddConnection(conn)
		if !exist {
			go s.acceptStream(sess)
		}
		select {
		case <-s.ctx.Done():
			return
		default:
			continue
		}
	}
}
func (s *Server) acceptStream(sess *Session) {
	for {
		stream, err := sess.Accept()
		//这里只会返回会话已关闭的错误
		if err != nil {
			if err == ErrBrokenSession {
				log.Infof("会话 %d 已关闭", sess.id)
				return
			} else {
				log.Error(err)
				return
			}
		}
		select {
		case s.connChan <- &Conn{
			rwc: stream,
		}:
		case <-s.ctx.Done():
			log.Debug("exiting")
			return
		}
	}
}
func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("multiplex server closed")
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
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	manage := &SessionManage{
		sessions: make(map[uint32]*Session),
	}
	server := &Server{
		manage:   manage,
		underlay: underlay,
		ctx:      ctx,
		cancel:   cancel,
		connChan: make(chan tunnel.Conn, 32),
	}
	if cfg.Multi.MaxConnNum <= 0 {
		server.sessConfig.MaxConnNum = 1
		server.sessConfig.Singleplex = true
	} else {
		server.sessConfig.MaxConnNum = cfg.Multi.MaxConnNum
		server.sessConfig.Singleplex = false
	}
	go server.acceptConnWorker()
	log.Debugf("multiplex server created")
	return server, nil
}
