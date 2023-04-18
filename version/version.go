package version

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh/handshake"
	"runtime"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/constant"
	"github.com/p4gefau1t/trojan-go/option"
)

type versionOption struct {
	flag *bool
}

func (*versionOption) Name() string {
	return "version"
}

func (*versionOption) Priority() int {
	return 10
}

func (c *versionOption) Handle() error {
	if *c.flag {
		fmt.Println("Trojan-Go", constant.Version)
		fmt.Println("Go Version:", runtime.Version())
		fmt.Println("OS/Arch:", runtime.GOOS+"/"+runtime.GOARCH)
		fmt.Println("Git Commit:", constant.Commit)
		fmt.Println("")
		fmt.Println("Developed by PageFault (p4gefau1t)")
		fmt.Println("Licensed under GNU General Public License version 3")
		fmt.Println("GitHub Repository:\thttps://github.com/p4gefau1t/trojan-go")
		fmt.Println("Trojan-Go Documents:\thttps://p4gefau1t.github.io/trojan-go/")
		return nil
	}
	return common.NewError("not set")
}

type keyOption struct {
	keyType *string
}

func (k *keyOption) Name() string {
	return "KEY"
}

func (k *keyOption) Handle() error {
	switch *k.keyType {
	case "ed25519":
		pri, pub, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		pri1, pub1, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		priS := base64.StdEncoding.EncodeToString(pri)
		pubS := base64.StdEncoding.EncodeToString(pub1)
		priC := base64.StdEncoding.EncodeToString(pri1)
		pubC := base64.StdEncoding.EncodeToString(pub)
		fmt.Printf("private key for server: %s\n", priS)
		fmt.Printf("public key for server: %s\n", pubS)
		fmt.Printf("private key for client: %s\n", priC)
		fmt.Printf("public key for client: %s", pubC)
		return nil
	case "x25519":
		pri, pub, err := handshake.GenerateKeyString()
		if err != nil {
			return err
		}
		fmt.Printf("key for server: %s\n", pri)
		fmt.Printf("key for client: %s\n", pub)
		return nil
	default:
		return common.NewError("not set")
	}
}
func (k *keyOption) Priority() int {
	return 1
}
func init() {
	option.RegisterHandler(&versionOption{
		flag: flag.Bool("version", false, "Display version and help info"),
	})
	option.RegisterHandler(&keyOption{
		keyType: flag.String("key", "", "generate key pairs for server and client"),
	})
}
