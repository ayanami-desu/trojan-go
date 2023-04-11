package simplesocks

import (
	"context"
	"github.com/p4gefau1t/trojan-go/tunnel/http2"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/tunnel"
	log "github.com/sirupsen/logrus"
)

const (
	Connect   tunnel.Command = 1
	Associate tunnel.Command = 3
)

type Client struct {
	writeMetadata bool
	underlay      tunnel.Client
}

func (c *Client) DialConn(addr *tunnel.Address, t tunnel.Tunnel) (tunnel.Conn, error) {
	metadata := &tunnel.Metadata{
		Command: Connect,
		Address: addr,
	}
	if c.writeMetadata {
		metadataBuf, err := metadataToBytes(metadata)
		if err != nil {
			return nil, err
		}
		conn, err := c.underlay.DialConn(nil, &Tunnel{})
		if err != nil {
			return nil, common.NewError("simplesocks failed to dial using underlying tunnel").Base(err)
		}
		return &Conn{
			Conn:          conn,
			isOutbound:    true,
			writeMetadata: c.writeMetadata,
			metadata:      metadata,
			metadataBuf:   metadataBuf,
		}, nil
	}
	conn, err := c.underlay.DialConn(addr, &Tunnel{})
	if err != nil {
		return nil, common.NewError("simplesocks failed to dial using underlying tunnel").Base(err)
	}
	return &Conn{
		Conn:          conn,
		writeMetadata: c.writeMetadata,
		metadata:      metadata,
	}, nil
}

func (c *Client) DialPacket(t tunnel.Tunnel) (tunnel.PacketConn, error) {
	conn, err := c.underlay.DialConn(nil, &Tunnel{})
	if err != nil {
		return nil, common.NewError("simplesocks failed to dial using underlying tunnel").Base(err)
	}
	metadata := &tunnel.Metadata{
		Command: Associate,
		Address: &tunnel.Address{
			DomainName:  "UDP_CONN",
			AddressType: tunnel.DomainName,
		},
	}
	if err := metadata.WriteTo(conn); err != nil {
		return nil, common.NewError("simplesocks failed to write udp associate").Base(err)
	}
	return &PacketConn{
		Conn: conn,
	}, nil
}

func (c *Client) Close() error {
	return c.underlay.Close()
}

func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	_, ok := underlay.(*http2.Client)
	log.Debug("simplesocks client created")
	return &Client{
		writeMetadata: !ok,
		underlay:      underlay,
	}, nil
}
