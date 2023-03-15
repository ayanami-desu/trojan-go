package multiplex

import (
	"context"
	"crypto/rand"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh"
	"io"
	"time"
)

type Client struct {
	sess       *Session
	sessConfig SessionConfig
	underlay   tunnel.Client
	ctx        context.Context
	cancel     context.CancelFunc
}

func (c *Client) newSession() error {
	connCh := make(chan tunnel.Conn, c.sessConfig.MaxConnNum)
	errCh := make(chan error)
	if underlay, ok := c.underlay.(*ssh.Client); ok {
		sessionId := make([]byte, 4)
		io.ReadFull(rand.Reader, sessionId)
		underlay.ReceiveSessionId(sessionId)
		c.sess = MakeSession(transSessionId(sessionId), c.sessConfig)
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
				c.sess.AddConnection(conn)
			case <-errCh:
				errNum += 1
				if errNum == 12 {
					return common.NewError("创建底层连接失败次数过多")
				}
			}
		}
		log.Debug("All underlying connections established")
		return nil
	} else {
		panic("暂不支持其他underlay")
	}

}
func (c *Client) DialConn(_ *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	if c.sess == nil || c.sessConfig.Singleplex || c.sess.IsClosed() {
		if err := c.newSession(); err != nil {
			return nil, err
		}
	}
	stream, err := c.sess.OpenStream()
	if err != nil {
		return nil, common.NewError(" open multiplex stream failed").Base(err)
	}
	return &Conn{
		rwc: stream,
	}, nil
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
	client.sessConfig.InactivityTimeout = time.Duration(cfg.Multi.StreamTimeout) * time.Second
	log.Debug("multiplex client created")
	return client, nil
}
