// wgproxy: userspace WireGuard (wireguard-go + gVisor netstack) exposed as a
// local HTTP proxy, built as a C archive for Locus.
//
// No NEPacketTunnelProvider / Network Extension entitlement is needed: the
// tunnel lives entirely inside the app process, and proxy-aware traffic
// (iOS Wi-Fi HTTP proxy) is dialed through it. If the tunnel is down, dials
// fail instead of falling back to the real network.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type peerConfig struct {
	PublicKey string `json:"public_key"` // base64
	Endpoint  string `json:"endpoint"`   // "ip:port"
}

type config struct {
	PrivateKey string     `json:"private_key"` // base64
	Address    string     `json:"address"`     // "10.x.x.x" or "10.x.x.x/32"
	DNS        string     `json:"dns"`
	MTU        int        `json:"mtu"`
	Listen     string     `json:"listen"` // must be loopback, e.g. "127.0.0.1:9080"
	Peer       peerConfig `json:"peer"`
}

var (
	mu       sync.Mutex
	dev      *device.Device
	listener net.Listener
	server   *http.Server
)

func main() {}

func cString(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid key")
	}
	return hex.EncodeToString(raw), nil
}

func peerUAPI(p peerConfig) (string, error) {
	pub, err := keyHex(p.PublicKey)
	if err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	if _, err := netip.ParseAddrPort(p.Endpoint); err != nil {
		return "", fmt.Errorf("peer endpoint: %w", err)
	}
	return "replace_peers=true\n" +
		"public_key=" + pub + "\n" +
		"endpoint=" + p.Endpoint + "\n" +
		"persistent_keepalive_interval=25\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"allowed_ip=::/0\n", nil
}

func stopLocked() {
	if server != nil {
		_ = server.Close()
		server = nil
	}
	if listener != nil {
		_ = listener.Close()
		listener = nil
	}
	if dev != nil {
		dev.Close()
		dev = nil
	}
}

func start(cfg config) error {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address must be loopback")
	}

	addr, err := netip.ParseAddr(strings.Split(cfg.Address, "/")[0])
	if err != nil {
		return fmt.Errorf("tunnel address: %w", err)
	}
	dns, err := netip.ParseAddr(cfg.DNS)
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1280
	}
	priv, err := keyHex(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	peer, err := peerUAPI(cfg.Peer)
	if err != nil {
		return err
	}

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, []netip.Addr{dns}, mtu)
	if err != nil {
		return fmt.Errorf("netstack: %w", err)
	}
	d := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wgproxy: "))
	if err := d.IpcSet("private_key=" + priv + "\n" + peer); err != nil {
		d.Close()
		return fmt.Errorf("configure: %w", err)
	}
	if err := d.Up(); err != nil {
		d.Close()
		return fmt.Errorf("up: %w", err)
	}

	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		d.Close()
		return fmt.Errorf("proxy listen: %w", err)
	}
	s := &http.Server{
		Handler:           &proxy{tnet: tnet},
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() { _ = s.Serve(l) }()

	dev, listener, server = d, l, s
	return nil
}

// LocusWGStart starts (or restarts) the tunnel + proxy. Returns NULL on
// success or an error string to free with LocusWGFree.
//
//export LocusWGStart
func LocusWGStart(cfgJSON *C.char) *C.char {
	var cfg config
	if err := json.Unmarshal([]byte(C.GoString(cfgJSON)), &cfg); err != nil {
		return cString("config: " + err.Error())
	}
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	if err := start(cfg); err != nil {
		return cString(err.Error())
	}
	return nil
}

// LocusWGSetPeer swaps the server (e.g. nearest relay changed) without
// restarting the proxy listener.
//
//export LocusWGSetPeer
func LocusWGSetPeer(peerJSON *C.char) *C.char {
	var p peerConfig
	if err := json.Unmarshal([]byte(C.GoString(peerJSON)), &p); err != nil {
		return cString("peer: " + err.Error())
	}
	uapi, err := peerUAPI(p)
	if err != nil {
		return cString(err.Error())
	}
	mu.Lock()
	defer mu.Unlock()
	if dev == nil {
		return cString("not running")
	}
	if err := dev.IpcSet(uapi); err != nil {
		return cString(err.Error())
	}
	return nil
}

//export LocusWGStop
func LocusWGStop() {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
}

// LocusWGStatus returns JSON: {"running","last_handshake","rx_bytes","tx_bytes"}.
//
//export LocusWGStatus
func LocusWGStatus() *C.char {
	mu.Lock()
	defer mu.Unlock()
	status := map[string]any{"running": dev != nil}
	if dev != nil {
		if uapi, err := dev.IpcGet(); err == nil {
			for _, line := range strings.Split(uapi, "\n") {
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				switch k {
				case "last_handshake_time_sec", "rx_bytes", "tx_bytes":
					n, _ := strconv.ParseInt(v, 10, 64)
					status[strings.TrimSuffix(k, "_time_sec")] = n
				}
			}
		}
	}
	out, _ := json.Marshal(status)
	return C.CString(string(out))
}

//export LocusWGFree
func LocusWGFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

// proxy is a minimal HTTP/1.1 forward proxy (CONNECT + absolute-URI requests)
// whose upstream connections are all dialed inside the WireGuard netstack.
type proxy struct {
	tnet *netstack.Net
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "Locus WireGuard proxy", http.StatusBadRequest)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	transport := &http.Transport{
		DialContext:         p.tnet.DialContext,
		Proxy:               nil,
		TLSHandshakeTimeout: 20 * time.Second,
	}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	upstream, err := p.tnet.DialContext(ctx, "tcp", r.Host)
	cancel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go pipe(upstream, client, buf.Reader)
}

func pipe(upstream, client net.Conn, buffered *bufio.Reader) {
	defer upstream.Close()
	defer client.Close()
	done := make(chan struct{}, 2)
	go func() {
		// Bytes the client sent right after CONNECT may sit in the reader.
		_, _ = io.Copy(upstream, buffered)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}
