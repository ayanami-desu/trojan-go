package singmux

import (
	"github.com/p4gefau1t/trojan-go/tunnel"
	M "github.com/sagernet/sing/common/metadata"
	"net/netip"
)

func convert(m *tunnel.Metadata) (*M.Socksaddr, error) {
	if m.IP != nil {
		addr, err := netip.ParseAddr(m.IP.String())
		if err != nil {
			return nil, err
		}
		return &M.Socksaddr{
			Addr: addr,
			Fqdn: m.DomainName,
			Port: uint16(m.Port),
		}, nil
	}
	return &M.Socksaddr{
		Fqdn: m.DomainName,
		Port: uint16(m.Port),
	}, nil
}

func parse(m M.Socksaddr) (*tunnel.Metadata, error) {
	addr, err := tunnel.NewAddressFromAddr(m.Network(), m.String())
	if err != nil {
		return nil, err
	}
	metadata := &tunnel.Metadata{
		Command: Connect,
		Address: addr,
	}
	return metadata, nil
}
