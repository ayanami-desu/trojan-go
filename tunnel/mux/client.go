package mux

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	singM "github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/smux"
	log "github.com/sirupsen/logrus"
)

// Client is a smux client
type Client struct {
	clientPoolLock sync.Mutex
	clientPool     list.List[*smuxClientInfo]
	underlay       tunnel.Client
	concurrency    int
	maxStreams     int
	minStreams     int
	maxConnections int
	idleTimeout    time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
}

func (c *Client) Close() error {
	c.cancel()
	c.clientPoolLock.Lock()
	defer c.clientPoolLock.Unlock()
	for _, element := range c.clientPool.Array() {
		element.client.Close()
	}
	return c.underlay.Close()
}

func (c *Client) cleanLoop() {
	var checkDuration time.Duration
	if c.idleTimeout <= 0 {
		checkDuration = time.Second * 10
		log.Warn("negative mux idleTimeout")
	} else {
		checkDuration = c.idleTimeout / 4
	}
	log.Debugf("check duration: %v s", checkDuration.Seconds())
	for {
		select {
		case <-time.After(checkDuration):
			c.clientPoolLock.Lock()
			for element := c.clientPool.Front(); element != nil; {
				nextElement := element.Next()
				if element.Value.client.IsClosed() {
					c.clientPool.Remove(element)
					element = nextElement
					continue
				}
				if element.Value.client.NumStreams() == 0 && time.Since(element.Value.lastActiveTime) > c.idleTimeout {
					element.Value.client.Close()
					element.Value.underlayConn.Close()
					c.clientPool.Remove(element)
				}
				element = nextElement
			}
			log.Debugf("current mux clients: %d", c.clientPool.Len())
			c.clientPoolLock.Unlock()
		case <-c.ctx.Done():
			log.Debug("shutting down mux cleaner...")
			c.clientPoolLock.Lock()
			for _, element := range c.clientPool.Array() {
				element.client.Close()
				element.underlayConn.Close()
			}
			c.clientPoolLock.Unlock()
			return
		}
	}
}

func (c *Client) DialConn(*tunnel.Address, tunnel.Tunnel) (tunnel.Conn, error) {
	var (
		session *smuxClientInfo
		stream  io.ReadWriteCloser
		err     error
	)
	for attempts := 0; attempts < 2; attempts++ {
		session, err = c.offer()
		if err != nil {
			continue
		}
		stream, err = session.client.Open()
		if err != nil {
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	session.lastActiveTime = time.Now()
	return &Conn{
		rwc:  stream,
		Conn: session.underlayConn,
	}, nil
}

func (c *Client) offer() (*smuxClientInfo, error) {
	c.clientPoolLock.Lock()
	defer c.clientPoolLock.Unlock()

	var sessions []abstractSession
	for element := c.clientPool.Front(); element != nil; {
		if element.Value.client.IsClosed() {
			nextElement := element.Next()
			c.clientPool.Remove(element)
			element = nextElement
			continue
		}
		sessions = append(sessions, element.Value)
		element = element.Next()
	}
	session := singM.MinBy(singM.Filter(sessions, abstractSession.CanTakeStream), abstractSession.NumStreams)
	if session == nil {
		return c.offerNew()
	}
	// 断言不会失败
	_session, _ := session.(*smuxClientInfo)
	numStreams := session.NumStreams()
	if numStreams == 0 {
		return _session, nil
	}
	if c.maxConnections > 0 {
		if len(sessions) >= c.maxConnections || numStreams < c.minStreams {
			return _session, nil
		}
	} else {
		if c.maxStreams > 0 && numStreams < c.maxStreams {
			return _session, nil
		}
	}
	return c.offerNew()
}

func (c *Client) offerNew() (*smuxClientInfo, error) {
	conn, err := c.underlay.DialConn(nil, nil)
	if err != nil {
		return nil, common.NewError("mux failed to dial").Base(err)
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.KeepAliveDisabled = true
	client, _ := smux.Client(conn, smuxConfig)
	info := &smuxClientInfo{
		client:         client,
		underlayConn:   conn,
		lastActiveTime: time.Now(),
		createdTime:    time.Now(),
	}
	c.clientPool.PushBack(info)
	return info, nil
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	if cfg.Mux.MaxConnTime > 60 {
		maxConnTime = time.Duration(cfg.Mux.MaxConnTime) * time.Second
	} else {
		maxConnTime = time.Duration(60) * time.Second
	}
	client := &Client{
		underlay:       underlay,
		maxConnections: cfg.Mux.MaxConnections,
		maxStreams:     cfg.Mux.MaxStreams,
		minStreams:     cfg.Mux.MinStreams,
		idleTimeout:    time.Duration(cfg.Mux.IdleTimeout) * time.Second,
		ctx:            ctx,
		cancel:         cancel,
	}
	go client.cleanLoop()
	log.Debug("mux client created")
	return client, nil
}
