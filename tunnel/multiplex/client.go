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
	sessIdleTime   time.Duration
	underlay       *ssh.Client
	ctx            context.Context
	cancel         context.CancelFunc
}

func (c *Client) newSession() (*Session, error) {
	log.Debugf("开始创建会话")
	connCh := make(chan tunnel.Conn, c.sessConfig.MaxConnNum)
	errCh := make(chan error)
	sessionId := make([]byte, 4)
	io.ReadFull(rand.Reader, sessionId)
	c.underlay.ReceiveSessionId(sessionId)
	sess := MakeSession(transSessionId(sessionId), c.sessConfig)
	for i := 0; i < c.sessConfig.MaxConnNum; i++ {
		go func() {
		makeconn:
			conn, err := c.underlay.DialConn(nil, &Tunnel{})
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

}

func (c *Client) cleanLoop() {
	var checkDuration time.Duration
	if c.sessIdleTime <= 0 {
		checkDuration = time.Second * 10
		log.Warn("negative sessIdleTime")
	} else {
		checkDuration = c.sessIdleTime / 4
	}
	log.Debugf("check duration: %v s", checkDuration.Seconds())
	for {
		select {
		case <-time.After(checkDuration):
			c.sessionsM.Lock()
			for id, info := range c.sessions {
				if info.streamCount() == 0 && time.Since(info.lastActiveTime) > c.sessIdleTime {
					info.Close()
					delete(c.sessions, id)
					log.Infof("session %d is closed due to inactivity", id)
				}
			}
			c.sessionsM.Unlock()
		case <-c.ctx.Done():
			log.Debug("shutting down session cleaner..")
			c.sessionsM.Lock()
			for id, info := range c.sessions {
				info.Close()
				delete(c.sessions, id)
				log.Debugf("session %d closed", id)
			}
			c.sessionsM.Unlock()
			return
		}
	}
}
func (c *Client) DialConn(_ *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	createStream := func(sess *Session) (tunnel.Conn, error) {
		stream, err := sess.OpenStream()
		if err != nil {
			return nil, common.NewError(" open multiplex stream failed").Base(err)
		}
		sess.lastActiveTime = time.Now()
		return &Conn{
			rwc: stream,
		}, nil
	}
	c.sessionsM.Lock()
	defer c.sessionsM.Unlock()
	for id, sess := range c.sessions {
		if sess.IsClosed() {
			delete(c.sessions, id)
			continue
		}
		if sess.streamCount() == 0 && time.Since(sess.lastActiveTime) > c.sessIdleTime {
			sess.SetTerminalMsg("timeout")
			sess.Close()
			log.Debugf("因不活跃而关闭会话: %v", id)
			delete(c.sessions, id)
			continue
		}
		if time.Since(sess.createdTime) > c.maxSessionTime {
			log.Debugf("因超时而跳过会话: %v", id)
			continue
		}
		return createStream(sess)
	}
	sess, err := c.newSession()
	c.sessions[sess.id] = sess
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
	sshClient, ok := underlay.(*ssh.Client)
	if !ok {
		log.Fatal("multiplex's underlay must be ssh client")
	}
	client := &Client{
		underlay: sshClient,
		ctx:      ctx,
		cancel:   cancel,
		sessions: make(map[uint32]*Session),
	}
	if cfg.Multi.MaxConnNum <= 0 {
		client.sessConfig.MaxConnNum = 1
		client.sessConfig.Singleplex = true
	} else {
		client.sessConfig.MaxConnNum = cfg.Multi.MaxConnNum
		client.sessConfig.Singleplex = false
	}
	client.maxSessionTime = time.Duration(cfg.Multi.MaxSessionTime) * time.Second
	client.sessIdleTime = time.Duration(cfg.Multi.SessIdleTime) * time.Second
	go client.cleanLoop()
	log.Debug("multiplex client created")
	return client, nil
}
