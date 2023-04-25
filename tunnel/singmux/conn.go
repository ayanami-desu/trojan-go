package singmux

import (
	"context"
	"github.com/p4gefau1t/trojan-go/tunnel"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/signal/done"
	"net"
)

type Conn struct {
	net.Conn
	metadata *tunnel.Metadata
	doneD    *done.Instance
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *Conn) Close() error {
	if c.doneD != nil {
		if c.doneD.Done() {
			return nil
		}
		c.doneD.Close()
	}
	return c.Conn.Close()
}

type dialer struct {
	underlay tunnel.Client
}

func (d *dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.underlay.DialConn(nil, nil)
}

func (d *dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	panic("implement me")
}

type serverHandler struct {
	server *Server
}

var handler *serverHandler

func (h *serverHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	m, err := parse(metadata.Destination)
	if err != nil {
		return err
	}
	d := done.New()
	h.server.connChan <- &Conn{
		Conn:     conn,
		metadata: m,
		doneD:    d,
	}
	<-d.Wait()
	return nil
}

func (h *serverHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	panic("implement me")
}

func (h *serverHandler) NewError(ctx context.Context, err error) {}
