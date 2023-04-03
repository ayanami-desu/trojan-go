package server

import (
	"context"
	"github.com/p4gefau1t/trojan-go/tunnel/http2"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh"

	"github.com/p4gefau1t/trojan-go/proxy"
	"github.com/p4gefau1t/trojan-go/tunnel/freedom"
	"github.com/p4gefau1t/trojan-go/tunnel/simplesocks"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
)

const Name = "SERVER"

func init() {
	proxy.RegisterProxyCreator(Name, func(ctx context.Context) (*proxy.Proxy, error) {
		//cfg := config.FromContext(ctx, Name).(*client.Config)
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

		root.BuildNext(ssh.Name).BuildNext(http2.Name).BuildNext(simplesocks.Name).IsEndpoint = true

		serverList := proxy.FindAllEndpoints(root)
		clientList, err := proxy.CreateClientStack(ctx, clientStack)
		if err != nil {
			cancel()
			return nil, err
		}
		return proxy.NewProxy(ctx, cancel, serverList, clientList), nil
	})
}
