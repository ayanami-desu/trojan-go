package http2

import (
	"context"
	"crypto/tls"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	icommon "github.com/p4gefau1t/trojan-go/tunnel/http2/common"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
	nhttp2 "golang.org/x/net/http2"
	"net"
	nhttp "net/http"
	"net/url"
	"time"
)

type Client struct {
	http2Transport *nhttp2.Transport
	http2Client    *nhttp.Client
	hostList       *host
	bufferSize     int32
	underlay       tunnel.Client
	ctx            context.Context
	cancel         context.CancelFunc
}

func (c *Client) cleanLoop(t int) {
	var checkDuration time.Duration
	if t <= 300 {
		checkDuration = time.Second * 30
	} else {
		checkDuration = time.Second * (time.Duration(t / 10))
	}
	log.Debugf("checkDuration is %v s", checkDuration.Seconds())
	for {
		select {
		case <-time.After(checkDuration):
			c.http2Transport.CloseIdleConnections()
			log.Debug("closed all idle connections")
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) DialConn(addr *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	preader, pwriter := pipe.New(pipe.WithSizeLimit(c.bufferSize))
	breader := &buf.BufferedReader{Reader: preader}
	request := &nhttp.Request{
		Method: "PUT",
		Host:   addr.String(),
		Body:   breader,
		URL: &url.URL{
			Scheme: "https",
			Host:   c.hostList.get(),
			Path:   "/c",
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		Header:     make(nhttp.Header),
	}
	// Disable any compression method from server.
	request.Header.Set("Accept-Encoding", "identity")
	wrc := &waitReadCloser{Wait: make(chan struct{})}
	go func() {
		response, err := c.http2Client.Do(request)
		if err != nil {
			log.Debugf("http2 failed to dial | %v", err)
			wrc.Close()
			return
		}
		if response.StatusCode != 200 {
			log.Debugf("unexpected status %v", response.StatusCode)
			wrc.Close()
			return
		}
		wrc.Set(response.Body)
	}()

	bwriter := buf.NewBufferedWriter(pwriter)
	icommon.Must(bwriter.SetBuffered(false))
	conn := newConnection(wrc, bwriter, icommon.ChainedClosable{breader, bwriter, wrc})
	return &Conn{
		Conn: conn,
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
	t := &nhttp2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return underlay.DialConn(nil, nil)
		}}
	if cfg.Http2.HealthCheckTimeout > 0 || cfg.Http2.IdleTimeout > 0 {
		t.ReadIdleTimeout = time.Duration(cfg.Http2.IdleTimeout) * time.Second
		t.PingTimeout = time.Duration(cfg.Http2.HealthCheckTimeout) * time.Second
	}
	httpClient := &nhttp.Client{Transport: t}
	hostList := generateHostList(time.Duration(cfg.Http2.MaxConnTime) * time.Second)
	client := &Client{
		http2Transport: t,
		http2Client:    httpClient,
		underlay:       underlay,
		bufferSize:     1024 * cfg.Http2.BufferSize,
		hostList:       hostList,
		ctx:            ctx,
		cancel:         cancel,
	}
	go client.cleanLoop(cfg.Http2.MaxConnTime)
	log.Debug("http2 client created")
	return client, nil
}
