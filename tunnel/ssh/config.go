package ssh

import "github.com/p4gefau1t/trojan-go/config"

type Config struct {
	Ssh SshConfig `json:"ssh" yaml:"ssh"`
}
type SshConfig struct {
	Pri          string `json:"pri" yaml:"pri"`
	Pub          string `json:"pub" yaml:"pub"`
	FastHkEnable bool   `json:"fastHkEnable" yaml:"fast-hk-enable"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			Ssh: SshConfig{
				FastHkEnable: false,
			},
		}
	})
}
