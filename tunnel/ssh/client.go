package ssh

import (
	"context"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh/handshake"
	log "github.com/sirupsen/logrus"
)

type Client struct {
	sessionId []byte
	hkFunc    handshake.HkFunc
	underlay  tunnel.Client
	ctx       context.Context
	cancel    context.CancelFunc
}

func (c *Client) ReceiveSessionId(id []byte) {
	if len(id) == 4 {
		c.sessionId = id
	} else {
		log.Fatalf("half sessionId should be 4 bytes")
	}
}
func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (c *Client) DialConn(_ *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := c.underlay.DialConn(nil, &Tunnel{})
	if err != nil {
		return nil, common.NewError("ssh failed to dial conn").Base(err)
	}
	//handshake.auth.SessionId = c.sessionId
	sshConn, err := c.hkFunc.HandShake(conn)
	if err != nil {
		conn.Close()
		return nil, common.NewError("ssh failed to handshake with remote server").Base(err)
	}
	return &Conn{
		Conn: sshConn,
	}, nil
}

func (c *Client) Close() error {
	return c.underlay.Close()
}
func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	hk := handshake.Init(cfg.Ssh.Pri, cfg.Ssh.Pub, cfg.Ssh.Rtt)
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		hkFunc:   hk,
		underlay: underlay,
		ctx:      ctx,
		cancel:   cancel,
	}
	log.Debug("ssh client created")
	return client, nil
}
