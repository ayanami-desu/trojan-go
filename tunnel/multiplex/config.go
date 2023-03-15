package multiplex

import "github.com/p4gefau1t/trojan-go/config"

type MultiplexConfig struct {
	MaxConnNum int `json:"maxConnNum" yaml:"max-conn-num"`
	StreamTimeout int `json:"streamTimeout" yaml:"stream-timeout"`
}

type Config struct {
	Multi MultiplexConfig `json:"multi" yaml:"multi"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			Multi: MultiplexConfig{
				MaxConnNum: 4,
				StreamTimeout: 300,
			},
		}
	})
}
