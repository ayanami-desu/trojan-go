package client

import (
	"context"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/proxy"
	"github.com/p4gefau1t/trojan-go/tunnel/adapter"
	"github.com/p4gefau1t/trojan-go/tunnel/http"
	"github.com/p4gefau1t/trojan-go/tunnel/http2"
	"github.com/p4gefau1t/trojan-go/tunnel/mux"
	"github.com/p4gefau1t/trojan-go/tunnel/simplesocks"
	"github.com/p4gefau1t/trojan-go/tunnel/singmux"
	"github.com/p4gefau1t/trojan-go/tunnel/socks"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
	log "github.com/sirupsen/logrus"
)

const Name = "CLIENT"

// GenerateClientTree generate general outbound protocol stack
func GenerateClientTree(ctx context.Context) []string {
	cfg := config.FromContext(ctx, Name).(*Config)
	clientStack := []string{transport.Name}
	var s string
	switch cfg.MuxType {
	case "http2":
		s = http2.Name
	case "mux":
		s = mux.Name
	case "sing-mux":
		s = singmux.Name
	case "nil":
		s = "nil"
	default:
		log.Fatalf("unknown mux type: %s", cfg.MuxType)
	}
	clientStack = append(clientStack, ssh.Name)
	if s != "nil" {
		clientStack = append(clientStack, s)
	}
	clientStack = append(clientStack, simplesocks.Name)
	return clientStack
}

func init() {
	proxy.RegisterProxyCreator(Name, func(ctx context.Context) (*proxy.Proxy, error) {
		adapterServer, err := adapter.NewServer(ctx, nil)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(ctx)

		root := &proxy.Node{
			Name:       adapter.Name,
			Next:       make(map[string]*proxy.Node),
			IsEndpoint: false,
			Context:    ctx,
			Server:     adapterServer,
		}

		root.BuildNext(http.Name).IsEndpoint = true
		root.BuildNext(socks.Name).IsEndpoint = true

		clientStack := GenerateClientTree(ctx)
		c, err := proxy.CreateClientStack(ctx, clientStack)
		if err != nil {
			cancel()
			return nil, err
		}
		s := proxy.FindAllEndpoints(root)
		return proxy.NewProxy(ctx, cancel, s, c), nil
	})
}
