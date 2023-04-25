package server

import (
	"context"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/proxy/client"
	"github.com/p4gefau1t/trojan-go/tunnel/http2"
	"github.com/p4gefau1t/trojan-go/tunnel/mux"
	"github.com/p4gefau1t/trojan-go/tunnel/singmux"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh"
	log "github.com/sirupsen/logrus"

	"github.com/p4gefau1t/trojan-go/proxy"
	"github.com/p4gefau1t/trojan-go/tunnel/freedom"
	"github.com/p4gefau1t/trojan-go/tunnel/simplesocks"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
)

const Name = "SERVER"

func init() {
	proxy.RegisterProxyCreator(Name, func(ctx context.Context) (*proxy.Proxy, error) {
		cfg := config.FromContext(ctx, Name).(*client.Config)
		ctx, cancel := context.WithCancel(ctx)
		transportServer, err := transport.NewServer(ctx, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		clientStack := []string{freedom.Name}

		root := &proxy.Node{
			Name:       transport.Name,
			Next:       make(map[string]*proxy.Node),
			IsEndpoint: false,
			Context:    ctx,
			Server:     transportServer,
		}

		var s string
		switch cfg.MuxType {
		case "http2":
			s = http2.Name
		case "mux":
			s = mux.Name
		case "sing-mux":
			s = singmux.Name
		default:
			s = ""
			log.Warnf("unknown mux type: %s", cfg.MuxType)
		}
		if s != "" {
			root.BuildNext(ssh.Name).BuildNext(s).BuildNext(simplesocks.Name).IsEndpoint = true
		} else {
			root.BuildNext(ssh.Name).BuildNext(simplesocks.Name).IsEndpoint = true
		}
		serverList := proxy.FindAllEndpoints(root)
		clientList, err := proxy.CreateClientStack(ctx, clientStack)
		if err != nil {
			cancel()
			return nil, err
		}
		return proxy.NewProxy(ctx, cancel, serverList, clientList), nil
	})
}
