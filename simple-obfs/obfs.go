package obfs

import (
	"net"

	"github.com/shadowsocks/go-shadowsocks2/simple-obfs/http"
	"github.com/shadowsocks/go-shadowsocks2/simple-obfs/tls"
)

func NewObfsServer(conn net.Conn, obfs string) net.Conn {
	switch obfs {
	case "tls":
		return tls.NewTLSObfsServer(conn)
	case "http":
		return http.NewHTTPObfsServer(conn)
	default:
		return conn
	}
}
