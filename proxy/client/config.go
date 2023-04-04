package client

import "github.com/p4gefau1t/trojan-go/config"

type Config struct {
	MuxType         string `json:"mux_type" yaml:"mux-type"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(Config)
	})
}
