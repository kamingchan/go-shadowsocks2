package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	lru "github.com/hashicorp/golang-lru"

	obfs "github.com/shadowsocks/go-shadowsocks2/simple-obfs"
	p "github.com/shadowsocks/go-shadowsocks2/simple-obfs/pool"
	"github.com/shadowsocks/go-shadowsocks2/snell"
)

const (
	CommandPing      byte = 0
	CommandConnect   byte = 1
	CommandConnectV2 byte = 5
	CommandUDP       byte = 6

	CommandUDPForward byte = 1

	ResponseTunnel byte = 0
	ResponseReady  byte = 0
	ResponsePong   byte = 1
	ResponseError  byte = 2

	Version byte = 1
)

func snellRemote(addr string, psk []byte) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	logf("listening TCP on %s", addr)
	if config.SimpleObfs != "" {
		logf("using simple-obfs mode %s", config.SimpleObfs)
	}
	first := snell.NewAES128GCM(psk)
	fallback := snell.NewChacha20Poly1305(psk)

	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %v", err)
			continue
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
		}

		go func() {
			defer c.Close()
			if config.TCPCork {
				c = timedCork(c, 10*time.Millisecond, 1280)
			}
			if config.SimpleObfs != "" {
				c = obfs.NewObfsServer(c, config.SimpleObfs)
			}
			sc := snell.NewConnWithFallback(c, first, fallback)

			target, command, err := readHeader(sc)
			if err != nil {
				return
			}

			switch command {
			case CommandPing:
				buf := []byte{ResponsePong}
				sc.Write(buf)
				return
			case CommandConnect:
				goto TCP
			case CommandUDP:
				handleUDPRequest(sc)
				return
			case CommandConnectV2:
				writeError(sc, errors.New("not supported"))
				return
			default:
				writeError(sc, errors.New("not supported"))
				return
			}

		TCP:
			rc, err := config.dialer.Dial("tcp", target)
			if err != nil {
				logf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()

			logf("proxy %s <-> %s", c.RemoteAddr(), target)
			if _, err = sc.Write([]byte{ResponseTunnel}); err != nil {
				logf("relay error: %v", err)
			}
			if err = relay(sc, rc); err != nil {
				logf("relay error: %v", err)
			}
		}()
	}
}

func readHeader(c net.Conn) (target string, cmd byte, err error) {
	buf := make([]byte, 255)
	if _, err = io.ReadFull(c, buf[:3]); err != nil {
		return
	}

	if buf[0] != Version {
		return
	}

	cmd = buf[1]
	clen := buf[2]
	if clen > 0 {
		if _, err = io.ReadFull(c, buf[:clen]); err != nil {
			return
		}
	}

	if cmd == CommandUDP {
		// udp request, skip reading in handshake stage
		return
	}

	if _, err = io.ReadFull(c, buf[:1]); err != nil {
		return
	}
	hlen := buf[0]
	if _, err = io.ReadFull(c, buf[:hlen+2]); err != nil {
		return
	}
	host := string(buf[:hlen])
	port := strconv.Itoa((int(buf[hlen]) << 8) | int(buf[hlen+1]))
	target = net.JoinHostPort(host, port)
	return
}

func writeError(conn net.Conn, err error) error {
	buf := bytes.NewBuffer([]byte{})
	buf.WriteByte(ResponseError)
	if e, ok := err.(syscall.Errno); ok {
		buf.WriteByte(byte(e))
	} else {
		buf.WriteByte(byte(0))
	}
	es := err.Error()
	if len(es) > 250 {
		es = es[0:250]
	}
	buf.WriteByte(byte(len(es)))
	buf.WriteString(es)
	_, el := conn.Write(buf.Bytes())
	return el
}

func handleUDPRequest(conn net.Conn) {
	cache, err := lru.New(256)
	if err != nil {
		// log.Errorf("UDP failed to create lru cache: %v\n", err)
		return
	}
	defer cache.Purge()

	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		// log.Errorf("UDP failed to listen: %v\n", err)
		writeError(conn, err)
		return
	} else {
		defer pc.Close()
		// log.V(1).Infof("UDP listening on: %s\n", pc.LocalAddr().String())
		if _, err := conn.Write([]byte{ResponseReady}); err != nil {
			// log.Errorf("Failed to write ResponseReady: %v\n", err)
			return
		}
	}

	go handleUDPIngress(conn, pc)

	buf := p.Get(p.RelayBufferSize)
	defer p.Put(buf)

uotLoop:
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// log.V(1).Infof("UDP over TCP read EOF, session ends\n")
			} else {
				// log.Errorf("UDP over TCP read error: %v\n", err)
			}
			break
		}

		if n < 5 {
			// log.Errorf("UDP over TCP insufficient chunk size: %d < 5\n", n)
			break
		}
		cmd := buf[0]
		hlen := buf[1]
		iplen := 0
		head := 2
		host := ""

		if cmd != CommandUDPForward {
			// log.Errorf("UDP over TCP unknown UDP command: 0x%x\n", cmd)
			break
		}
		if hlen == 0 {
			switch buf[2] {
			case 4:
				iplen = 4
			case 6:
				iplen = 16
			default:
				// log.Errorf("Unknown IP Version: 0x%x\n", buf[2])
				break uotLoop
			}

			head = 3 + iplen /* now points to port */
			if n < head+2 {
				// log.Errorf("UDP over TCP insufficient chunk size: %d < %d\n", n, head+2)
				break
			}
			ip := net.IP(buf[3:head])
			host = ip.String()
		} else {
			head = 2 + int(hlen)
			if n < head+2 {
				// log.Errorf("UDP over TCP insufficient chunk size: %d < %d\n", n, head+2)
				break
			}
			host = string(buf[2:head])
		}
		port := (int(buf[head]) << 8) | int(buf[head+1])
		head += 2
		target := net.JoinHostPort(host, strconv.Itoa(port))
		// log.V(1).Infof("UDP over TCP forwarding to %s\n", target)

		var uaddr *net.UDPAddr
		if value, ok := cache.Get(target); ok {
			uaddr = value.(*net.UDPAddr)
			// log.V(1).Infof("UDP cache hit: %s -> %s\n", target, uaddr.String())
		} else {
			uaddr, err = net.ResolveUDPAddr("udp", target)
			if err != nil {
				// log.Warningf("UDP over TCP failed to resolve %s: %v\n", target, err)
				/* won't close connection, but cause this packet losses */
			}
			// log.V(1).Infof("UDP over TCP resolved target %s -> %s\n", target, uaddr.String())
			cache.Add(target, uaddr)
		}

		payloadSize := n - head
		if payloadSize > 0 {
			// log.V(1).Infof("UDP over TCP forward %d bytes to target %s\n", payloadSize, target)
			_, err = pc.WriteTo(buf[head:n], uaddr)
			if err != nil {
				// log.Errorf("UDP over TCP  failed to write to %s: %v\n", target, err)
				break
			}
		}
	}
}

func handleUDPIngress(conn net.Conn, pc net.PacketConn) {
	buf := p.Get(p.RelayBufferSize)
	defer p.Put(buf)

	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				// log.Errorf("UDP failed to read: %v\n", err)
			}
			break
		}
		// log.V(1).Infof("UDP read %d bytes from %s\n", n, raddr.String())

		uaddr := raddr.(*net.UDPAddr)
		ipver := 4
		if uaddr.IP.To4() == nil {
			ipver = 6
		}
		buffer := bytes.NewBuffer([]byte{})
		buffer.WriteByte(byte(ipver))
		switch ipver {
		case 4:
			buffer.Write(uaddr.IP.To4())
		case 6:
			buffer.Write(uaddr.IP.To16())
		}
		buffer.Write([]byte{byte(uaddr.Port >> 8), byte(uaddr.Port & 0xff)})
		buffer.Write(buf[:n])

		_, err = conn.Write(buffer.Bytes())
		if err != nil {
			// log.Errorf("UDP failed to write back: %v\n", err)
			break
		}
	}
}
