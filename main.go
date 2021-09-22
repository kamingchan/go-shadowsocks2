package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/benburkert/dns"
	"golang.org/x/net/proxy"

	"github.com/shadowsocks/go-shadowsocks2/core"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
	TCPCork    bool
	SimpleObfs string
	Proxy      string

	dialer proxy.Dialer
}

func main() {

	var flags struct {
		Server     string
		Cipher     string
		Key        string
		Password   string
		Keygen     int
		UDP        bool
		TCP        bool
		Plugin     string
		PluginOpts string
		DNS        string
	}

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
	flag.IntVar(&flags.Keygen, "keygen", 0, "generate a base64url-encoded random key of given length in byte")
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.StringVar(&flags.Plugin, "plugin", "", "Enable SIP003 plugin. (e.g., v2ray-plugin)")
	flag.StringVar(&flags.PluginOpts, "plugin-opts", "", "Set SIP003 plugin options. (e.g., \"server;tls;host=mydomain.me\")")
	flag.BoolVar(&flags.UDP, "udp", false, "(server-only) enable UDP support")
	flag.BoolVar(&flags.TCP, "tcp", true, "(server-only) enable TCP support")
	flag.BoolVar(&config.TCPCork, "tcpcork", false, "coalesce writing first few packets")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.StringVar(&config.SimpleObfs, "simpleobfs", "", "(server-only) enable built-in simple obfs")
	flag.StringVar(&config.Proxy, "proxy", "", "(server-only) server proxy")
	flag.StringVar(&flags.DNS, "dns", "", "(server-only) enable built-in dns client")
	flag.Parse()

	if flags.DNS != "" {
		servers := strings.Split(flags.DNS, ",")
		parsed := make([]net.Addr, len(servers))
		for idx, server := range servers {
			host, _port, err := net.SplitHostPort(server)
			if err != nil {
				log.Fatal(err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				log.Fatalf("invalid dns server: %s", server)
			}
			port, err := strconv.Atoi(_port)
			if err != nil {
				log.Fatalf("invalid dns server: %s", server)
			}
			parsed[idx] = &net.UDPAddr{
				IP:   ip,
				Port: port,
			}
		}
		logf("set dns client: %v", servers)
		ns := dns.NameServers(parsed).RoundRobin()
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial:     (&dns.Client{Transport: &dns.Transport{Proxy: ns}}).Dial,
		}
	}

	if flags.Keygen > 0 {
		key := make([]byte, flags.Keygen)
		io.ReadFull(rand.Reader, key)
		fmt.Println(base64.URLEncoding.EncodeToString(key))
		return
	}

	if flags.Server == "" {
		flag.Usage()
		return
	}

	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}

	if flags.Server != "" { // server mode
		addr := flags.Server
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		udpAddr := addr

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, true)
			if err != nil {
				log.Fatal(err)
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		config.dialer = proxy.Direct
		if config.Proxy != "" {
			proxyURL, err := url.Parse(config.Proxy)
			if err != nil {
				log.Fatal(err)
			}
			dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
			if err != nil {
				log.Fatal(err)
			}
			config.dialer = dialer
		}

		if flags.UDP {
			go udpRemote(udpAddr, ciph.PacketConn)
		}
		if flags.TCP {
			go tcpRemote(addr, ciph.StreamConn)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	killPlugin()
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
