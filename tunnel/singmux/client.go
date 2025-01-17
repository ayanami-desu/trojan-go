package singmux

import (
	"context"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	smux "github.com/sagernet/sing-mux"
	log "github.com/sirupsen/logrus"
	"time"
)

const (
	Connect   tunnel.Command = 1
	Associate tunnel.Command = 3
)

type Client struct {
	singClient    *smux.Client
	checkDuration time.Duration
	underlay      tunnel.Client
	ctx           context.Context
	cancel        context.CancelFunc
}

func (c *Client) cleanLoop() {
	log.Debugf("start sing-mux clean loop: %v min timeout", c.checkDuration.Minutes())
	for {
		select {
		case <-time.After(c.checkDuration):
			c.singClient.Reset()
			log.Debug("reset all sing-mux session")
		case <-c.ctx.Done():
			log.Debug("shutting down sing-mux cleaner...")
			return
		}
	}
}

func (c *Client) DialConn(addr *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	m := &tunnel.Metadata{
		Command: Connect,
		Address: addr,
	}
	metadata, err := convert(m)
	if err != nil {
		return nil, err
	}
	conn, err := c.singClient.DialContext(c.ctx, m.Network(), *metadata)
	return &Conn{
		Conn:     conn,
		metadata: m,
	}, nil
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("implement me")
}

func (c *Client) Close() error {
	c.cancel()
	if err := c.singClient.Close(); err != nil {
		return err
	}
	return c.underlay.Close()
}

func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	option := smux.Options{
		Dialer:         &dialer{underlay},
		Protocol:       cfg.Mux.Protocol,
		MaxConnections: cfg.Mux.MaxConnections,
		MinStreams:     cfg.Mux.MinStreams,
		MaxStreams:     cfg.Mux.MaxStreams,
		Padding:        cfg.Mux.Padding,
	}
	sc, err := smux.NewClient(option)
	common.Must(err)
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		singClient:    sc,
		checkDuration: time.Duration(cfg.Mux.ResetTimeout) * 60 * time.Second,
		underlay:      underlay,
		ctx:           ctx,
		cancel:        cancel,
	}
	if cfg.Mux.ResetTimeout >= 5 {
		go client.cleanLoop()
	} else {
		log.Warnf("session reset timeout %d min is too short", cfg.Mux.ResetTimeout)
	}
	log.Debugf("sing-mux of %s client created", cfg.Mux.Protocol)
	return client, nil
}
