package multiplex

import "github.com/p4gefau1t/trojan-go/config"

type MultiplexConfig struct {
	MaxConnNum     int `json:"maxConnNum" yaml:"max-conn-num"`
	MaxSessionTime int `json:"streamTimeout" yaml:"stream-timeout"`
	SessIdleTime   int `json:"sessIdleTime" yaml:"sess-idle-time"`
}

type Config struct {
	Multi MultiplexConfig `json:"multi" yaml:"multi"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			Multi: MultiplexConfig{
				MaxConnNum:     4,
				MaxSessionTime: 300,
				SessIdleTime:   60,
			},
		}
	})
}
