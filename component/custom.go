//go:build custom || full
// +build custom full

package build

import (
	_ "github.com/p4gefau1t/trojan-go/proxy/custom"
	_ "github.com/p4gefau1t/trojan-go/tunnel/adapter"
	_ "github.com/p4gefau1t/trojan-go/tunnel/freedom"
	_ "github.com/p4gefau1t/trojan-go/tunnel/http2"
	_ "github.com/p4gefau1t/trojan-go/tunnel/multiplex"
	_ "github.com/p4gefau1t/trojan-go/tunnel/mux"
	_ "github.com/p4gefau1t/trojan-go/tunnel/simplesocks"
	_ "github.com/p4gefau1t/trojan-go/tunnel/socks"
	_ "github.com/p4gefau1t/trojan-go/tunnel/ssh"
	_ "github.com/p4gefau1t/trojan-go/tunnel/transport"
)
