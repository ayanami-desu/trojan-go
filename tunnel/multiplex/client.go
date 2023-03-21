package multiplex

import (
	"context"
	"crypto/rand"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh"
	log "github.com/sirupsen/logrus"
	"io"
	"sync"
	"time"
)

type Client struct {
	sessionsM      sync.RWMutex
	sessions       map[uint32]*Session
	sessConfig     SessionConfig
	maxSessionTime time.Duration
	underlay       tunnel.Client
	ctx            context.Context
	cancel         context.CancelFunc
}

func (c *Client) newSession() (*Session, error) {
	connCh := make(chan tunnel.Conn, c.sessConfig.MaxConnNum)
	errCh := make(chan error)
	if underlay, ok := c.underlay.(*ssh.Client); ok {
		sessionId := make([]byte, 4)
		io.ReadFull(rand.Reader, sessionId)
		underlay.ReceiveSessionId(sessionId)
		sess := MakeSession(transSessionId(sessionId), c.sessConfig)
		for i := 0; i < c.sessConfig.MaxConnNum; i++ {
			go func() {
			makeconn:
				conn, err := underlay.DialConn(nil, &Tunnel{})
				if err != nil {
					errCh <- err
					log.Errorf("Failed to prepare connection to remote: %w", err)
					time.Sleep(time.Second * 3)
					goto makeconn
				}
				connCh <- conn
			}()
		}
		errNum := 0

		for i := 0; i < c.sessConfig.MaxConnNum; i++ {
			select {
			case conn := <-connCh:
				sess.AddConnection(conn)
			case <-errCh:
				errNum += 1
				if errNum == 12 {
					return nil, common.NewError("创建底层连接失败次数过多")
				}
			}
		}
		log.Debug("All underlying connections established")
		return sess, nil
	} else {
		panic("暂不支持其他underlay")
	}

}
func (c *Client) DialConn(_ *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	createStream := func(sess *Session) (tunnel.Conn, error) {
		stream, err := sess.OpenStream()
		if err != nil {
			return nil, common.NewError(" open multiplex stream failed").Base(err)
		}
		return &Conn{
			rwc: stream,
		}, nil
	}
	c.sessionsM.Lock()
	defer c.sessionsM.Unlock()
	for _, sess := range c.sessions {
		if sess.IsClosed() {
			delete(c.sessions, sess.id)
			continue
		}
		if sess.streamCount() == 0 && !sess.IsClosed() {
			sess.SetTerminalMsg("timeout")
			sess.Close()
			delete(c.sessions, sess.id)
			continue
		}
		if time.Since(sess.createdTime) > c.maxSessionTime {
			continue
		}
		return createStream(sess)
	}
	sess, err := c.newSession()
	if err != nil {
		return nil, err
	}
	return createStream(sess)
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (c *Client) Close() error {
	c.cancel()
	return c.underlay.Close()
}
func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		underlay: underlay,
		ctx:      ctx,
		cancel:   cancel,
	}
	if cfg.Multi.MaxConnNum <= 0 {
		client.sessConfig.MaxConnNum = 1
		client.sessConfig.Singleplex = true
	} else {
		client.sessConfig.MaxConnNum = cfg.Multi.MaxConnNum
		client.sessConfig.Singleplex = false
	}
	client.maxSessionTime = time.Duration(cfg.Multi.MaxSessionTime) * time.Second
	log.Debugf("multiplex client created")
	return client, nil
}
