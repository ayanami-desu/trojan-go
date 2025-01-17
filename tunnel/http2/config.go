package http2

import "github.com/p4gefau1t/trojan-go/config"

type Http2Config struct {
	MaxConnTime        int   `json:"maxConnTime" yaml:"max-conn-time"`
	BufferSize         int32 `json:"bufferSize" yaml:"buffer-size"`
	TimeOut            int   `json:"timeOut" yaml:"time-out"`
	IdleTimeout        int   `json:"idleTimeout" yaml:"idle-timeout"`
	HealthCheckTimeout int   `json:"healthCheckTimeout" yaml:"health-check-timeout"`
}

type Config struct {
	Http2 Http2Config `json:"http2" yaml:"http2"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			Http2: Http2Config{
				MaxConnTime:        600,
				BufferSize:         512,
				TimeOut:            1,
				IdleTimeout:        30,
				HealthCheckTimeout: 5,
			},
		}
	})
}
