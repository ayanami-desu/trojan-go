package mux

import "github.com/p4gefau1t/trojan-go/config"

type MuxConfig struct {
	IdleTimeout    int `json:"idle_timeout" yaml:"idle-idleTimeout"`
	MaxConnections int `json:"max_connections" yaml:"max-connections"`
	MinStreams     int `json:"min_streams" yaml:"min-streams"`
	MaxStreams     int `json:"max_streams" yaml:"max-streams"`
	MaxConnTime    int `json:"max_conn_time" yaml:"max-conn-time"`
}

type Config struct {
	Mux MuxConfig `json:"mux" yaml:"mux"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			Mux: MuxConfig{
				IdleTimeout: 60,
				//MaxStreams:  8,
				MaxConnections: 4,
				MinStreams:     8,
				MaxConnTime:    600,
			},
		}
	})
}
