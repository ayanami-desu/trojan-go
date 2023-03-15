package mux

import "github.com/p4gefau1t/trojan-go/config"

type MuxConfig struct {
	IdleTimeout int `json:"idle_timeout" yaml:"idle-timeout"`
	Concurrency int `json:"concurrency" yaml:"concurrency"`
}

type Config struct {
	Mux MuxConfig `json:"mux" yaml:"mux"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			Mux: MuxConfig{
				IdleTimeout: 60,
				Concurrency: 8,
			},
		}
	})
}
