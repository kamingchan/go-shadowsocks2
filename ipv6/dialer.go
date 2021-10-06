package ipv6

import (
	"net"

	"golang.org/x/net/proxy"
)

var Dialer proxy.Dialer = &dialer{}

type dialer struct {
}

func (i *dialer) Dial(network, addr string) (conn net.Conn, err error) {
	// resolve hostname manually
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var (
		v4 = make([]net.IP, len(ips))
		v6 = make([]net.IP, len(ips))
	)
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	for _, ip := range append(v6, v4...) {
		address := net.JoinHostPort(ip.String(), port)
		conn, err = net.Dial(network, address)
		if err != nil {
			continue
		}
		return conn, nil
	}
	return nil, err
}
