package singmux

import "github.com/p4gefau1t/trojan-go/config"

type MuxConfig struct {
	Protocol       string `json:"protocol" yaml:"protocol"`
	MaxConnections int    `json:"max_connections" yaml:"max-connections"`
	MinStreams     int    `json:"min_streams" yaml:"min-streams"`
	MaxStreams     int    `json:"max_streams" yaml:"max-streams"`
	Padding        bool   `json:"padding" yaml:"padding"`
}

type Config struct {
	Mux MuxConfig `json:"singmux" yaml:"sing-mux"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			Mux: MuxConfig{
				Protocol:   "smux",
				MaxStreams: 8,
				Padding:    false,
			},
		}
	})
}
