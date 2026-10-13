package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type candidate struct{ device Device }
type Gateway struct {
	cfg          *RuntimeConfig
	reg          *Registry
	httpClient   *http.Client
	work         chan candidate
	probes       []chan struct{}
	seq          string
	instance     string
	messageCount atomic.Uint64
	stats        struct {
		packets      atomic.Uint64
		responses    atomic.Uint64
		discovered   atomic.Uint64
		verifyFailed atomic.Uint64
		httpGets     atomic.Uint64
		dropQueue    atomic.Uint64
	}
}

func newGateway(c *RuntimeConfig) (*Gateway, error) {
	r, err := newRegistry(c)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy: nil, MaxIdleConns: 256, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 32,
		IdleConnTimeout:       30 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	g := &Gateway{cfg: c, reg: r, httpClient: &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		work: make(chan candidate, 2048), probes: make([]chan struct{}, len(c.Sources)), seq: newUUID(),
		instance: strconv.FormatInt(time.Now().Unix(), 10)}
	for i := range g.probes {
		g.probes[i] = make(chan struct{}, 1)
	}
	return g, nil
}
func (g *Gateway) rescan() {
	for _, ch := range g.probes {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
func (g *Gateway) verify(d Device) (string, bool) {
	if !g.cfg.Config.VerifyMetadata {
		return "", true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	target := fmt.Sprintf("http://%s%s", net.JoinHostPort(d.IP, strconv.Itoa(d.Port)), d.Path)
	req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(makeMetadataGet(d.UUID)))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	res, err := g.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if err != nil || len(body) > 2*1024*1024 || !bytes.Contains(body, []byte("GetResponse")) || !bytes.Contains(body, []byte("Envelope")) || bytes.Contains(body, []byte("<soap:Fault")) {
		return "", false
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	var last string
	for {
		tk, e := dec.Token()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return "", false
		}
		switch t := tk.(type) {
		case xml.StartElement:
			if t.Name.Space == nsComputer && t.Name.Local == "Computer" {
				last = "Computer"
			} else {
				last = ""
			}
		case xml.CharData:
			if last == "Computer" {
				text := strings.TrimSpace(string(t))
				if text != "" {
					return strings.SplitN(text, "/", 2)[0], true
				}
			}
		case xml.EndElement:
			last = ""
		}
	}
	return "", true
}
func (g *Gateway) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-g.work:
			name, ok := g.verify(task.device)
			if ok {
				d := task.device
				if name != "" && len(name) <= 80 {
					d.Name = name
				}
				g.reg.finish(d, true)
				g.stats.discovered.Add(1)
				log.Printf("discovered UUID=%s host=%s origin=%s metadata=%s", d.UUID, d.IP, d.Origin, d.Path)
			} else {
				g.reg.finish(task.device, false)
				g.stats.verifyFailed.Add(1)
				log.Printf("verification failed UUID=%s source=%s", task.device.UUID, task.device.IP)
			}
		}
	}
}
func (g *Gateway) handleSource(ep Endpoint, from *net.UDPAddr, data []byte) {
	if from == nil || from.IP.To4() == nil || from.Port != 3702 || !anyAllowed(from.IP, ep.Network) {
		return
	}
	if from.IP.Equal(ep.IP) {
		return
	}
	msg, err := parseWSD(data)
	if err != nil {
		return
	}
	if msg.Action != nsWSD+"/ProbeMatches" && msg.Action != nsWSD+"/ResolveMatches" {
		return
	}
	if len(msg.Types) == 0 {
		return
	}
	id := strings.TrimPrefix(strings.ToLower(msg.Target), "urn:uuid:")
	if !validUUID(id) {
		return
	}
	path, port, ok := parseXAddr(msg, from.IP, g.cfg.AllowedPorts)
	if !ok {
		return
	}
	if !g.reg.begin(id, from.IP.String()) {
		return
	}
	d := Device{UUID: id, Name: "", IP: from.IP.String(), Port: port, Path: path, Origin: ep.Name,
		Types: msg.Types, MetadataVersion: msg.MetadataVersion, LastSeen: time.Now()}
	select {
	case g.work <- candidate{device: d}:
	default:
		g.reg.finish(d, false)
		g.stats.dropQueue.Add(1)
	}
}
func (g *Gateway) sourceLoop(ctx context.Context, ep Endpoint, index int, errorsChan chan<- error) {
	// Bind to the selected interface address and a random local UDP port.
	// This socket receives WSD unicast ProbeMatches directly, no packet capture.
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ep.IP, Port: 0})
	if err != nil {
		reportError(errorsChan, fmt.Errorf("scan bind %s: %w", ep.Name, err))
		return
	}
	defer u.Close()
	raw, err := u.SyscallConn()
	if err != nil {
		reportError(errorsChan, err)
		return
	}
	var optErr error
	err = raw.Control(func(fd uintptr) {
		var a [4]byte
		copy(a[:], ep.IP.To4())
		optErr = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, a)
		if optErr == nil {
			optErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 1)
		}
	})
	if err != nil {
		reportError(errorsChan, err)
		return
	}
	if optErr != nil {
		reportError(errorsChan, fmt.Errorf("set multicast source on %s: %w", ep.Name, optErr))
		return
	}
	if err = u.SetReadBuffer(2 * 1024 * 1024); err != nil {
		log.Printf("UDP buffer warning: %v", err)
	}
	go func() {
		ticker := time.NewTicker(g.cfg.ProbeInterval)
		defer ticker.Stop()
		addr := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 3702}
		for {
			p := makeProbe()
			if _, err := u.WriteToUDP(p, addr); err != nil {
				log.Printf("probe %s: %v", ep.Name, err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-g.probes[index]:
			}
		}
	}()
	buf := make([]byte, 32769)
	log.Printf("source %s: %s network=%s probe every %s", ep.Name, ep.IP, ep.Net, g.cfg.ProbeInterval)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = u.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := u.ReadFromUDP(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue
		}
		if err != nil {
			reportError(errorsChan, fmt.Errorf("source recv %s: %w", ep.Name, err))
			return
		}
		if n > 32768 {
			continue
		}
		g.handleSource(ep, addr, buf[:n])
	}
}
func (g *Gateway) chooseReply(req WSDMessage, ep Endpoint) []Device {
	list := g.reg.snapshot()
	if len(list) == 0 {
		return nil
	}
	if req.Action == nsWSD+"/Resolve" {
		id := strings.TrimPrefix(strings.ToLower(req.Target), "urn:uuid:")
		dev, ok := g.reg.get(id)
		if ok {
			return []Device{dev}
		}
		return nil
	}
	if req.Action != nsWSD+"/Probe" {
		return nil
	}
	limit := g.cfg.Config.MaxResponsesPerProbe
	if limit > len(list) {
		limit = len(list)
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(req.MessageID))
	start := int(h.Sum32()) % len(list)
	out := make([]Device, 0, limit)
	for i := 0; i < len(list) && len(out) < limit; i++ {
		d := list[(start+i)%len(list)]
		if matchesProbe(req, d) {
			out = append(out, d)
		}
	}
	return out
}
func (g *Gateway) clientLoop(ctx context.Context, ep Endpoint, errorsChan chan<- error) {
	u, err := net.ListenMulticastUDP("udp4", ep.Iface, &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 3702})
	if err != nil {
		reportError(errorsChan, fmt.Errorf("multicast join client %s: %w", ep.Name, err))
		return
	}
	defer u.Close()
	_ = u.SetReadBuffer(2 * 1024 * 1024)
	// A fixed number of workers and bounded queue, not a goroutine per packet.
	type packet struct {
		data []byte
		from *net.UDPAddr
	}
	queue := make(chan packet, 1024)
	var wg sync.WaitGroup
	var dedupe sync.Map // sourceIP + MessageID -> time.Time
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case p := <-queue:
					if p.from == nil || !anyAllowed(p.from.IP, ep.Network) || p.from.IP.Equal(ep.IP) {
						continue
					}
					req, err := parseWSD(p.data)
					if err != nil || req.MessageID == "" {
						continue
					}
					if req.Action != nsWSD+"/Probe" && req.Action != nsWSD+"/Resolve" {
						continue
					}
					key := p.from.IP.String() + "/" + req.MessageID
					if old, ok := dedupe.Load(key); ok && time.Since(old.(time.Time)) < 4*time.Second {
						continue
					}
					dedupe.Store(key, time.Now())
					if len(g.reg.snapshot()) == 0 {
						g.rescan()
					}
					devices := g.chooseReply(req, ep)
					kind := "ProbeMatches"
					if req.Action == nsWSD+"/Resolve" {
						kind = "ResolveMatches"
					}
					for _, d := range devices {
						// The advertised XAddr is on the client's own interface subnet.
						xaddr := fmt.Sprintf("http://%s/%s/", net.JoinHostPort(ep.IP.String(), strconv.Itoa(g.cfg.Config.HTTPPort)), d.UUID)
						pkt := writeReply(kind, req.MessageID, g.seq, g.instance, g.messageCount.Add(1), d, xaddr)
						if len(pkt) > 32768 {
							continue
						}
						if _, err := u.WriteToUDP(pkt, p.from); err == nil {
							g.stats.responses.Add(1)
						}
					}
				}
			}
		}()
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				dedupe.Range(func(k, v any) bool {
					if time.Since(v.(time.Time)) > time.Minute {
						dedupe.Delete(k)
					}
					return true
				})
			}
		}
	}()
	log.Printf("client %s: %s %s HTTP=%d", ep.Name, ep.IP, ep.Net, g.cfg.Config.HTTPPort)
	buf := make([]byte, 32769)
	for {
		if ctx.Err() != nil {
			close(queue)
			wg.Wait()
			return
		}
		_ = u.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := u.ReadFromUDP(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue
		}
		if err != nil {
			reportError(errorsChan, fmt.Errorf("client recv %s: %w", ep.Name, err))
			return
		}
		if n > 32768 || !anyAllowed(addr.IP, ep.Network) {
			continue
		}
		g.stats.packets.Add(1)
		copyPkt := append([]byte(nil), buf[:n]...)
		select {
		case queue <- packet{copyPkt, addr}:
		default:
			g.stats.dropQueue.Add(1)
		}
	}
}
func reportError(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}
func (g *Gateway) httpHandler(ep Endpoint) http.Handler {
	semaphore := make(chan struct{}, g.cfg.Config.HTTPConcurrency)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iphost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !anyAllowed(net.ParseIP(iphost), ep.Network) {
			http.Error(w, "forbidden", 403)
			return
		}
		if r.Method != "POST" || r.URL.RawQuery != "" {
			http.Error(w, "only SOAP metadata POST", 405)
			return
		}
		// Advertise /UUID/ and preserve upstream original path precisely.
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(segments) != 1 || !validUUID(segments[0]) {
			http.NotFound(w, r)
			return
		}
		d, ok := g.reg.get(segments[0])
		if !ok {
			http.NotFound(w, r)
			return
		}
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
		default:
			http.Error(w, "busy", 503)
			return
		}
		if r.ContentLength > 65536 {
			http.Error(w, "too large", 413)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || len(body) > 65536 {
			http.Error(w, "too large", 413)
			return
		}
		if !bytes.Contains(body, []byte(actionGet)) {
			http.Error(w, "unsupported SOAP action", 400)
			return
		}
		target := fmt.Sprintf("http://%s%s", net.JoinHostPort(d.IP, strconv.Itoa(d.Port)), d.Path)
		req, err := http.NewRequestWithContext(r.Context(), "POST", target, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
		res, err := g.httpClient.Do(req)
		if err != nil {
			log.Printf("upstream error %s: %v", d.IP, err)
			http.Error(w, "upstream unavailable", 502)
			return
		}
		defer res.Body.Close()
		if ct := res.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(res.Body, 2*1024*1024))
		g.stats.httpGets.Add(1)
	})
}
func (g *Gateway) metadataLoop(ctx context.Context, ep Endpoint, errorsChan chan<- error) {
	addr := net.JoinHostPort(ep.IP.String(), strconv.Itoa(g.cfg.Config.HTTPPort))
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		reportError(errorsChan, fmt.Errorf("metadata bind %s: %w", addr, err))
		return
	}
	server := &http.Server{Handler: g.httpHandler(ep), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	go func() {
		<-ctx.Done()
		s, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = server.Shutdown(s)
	}()
	log.Printf("metadata HTTP listening %s", addr)
	if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		reportError(errorsChan, err)
	}
}
func (g *Gateway) statusSnapshot() any {
	return map[string]any{
		"version": version, "devices": g.reg.snapshot(), "stats": map[string]uint64{
			"client_probes": g.stats.packets.Load(), "wsd_replies": g.stats.responses.Load(),
			"discovered": g.stats.discovered.Load(), "verify_failed": g.stats.verifyFailed.Load(),
			"http_gets": g.stats.httpGets.Load(), "dropped": g.stats.dropQueue.Load(),
		},
	}
}
func (g *Gateway) adminLoop(ctx context.Context, errorsChan chan<- error) {
	socket := g.cfg.Config.AdminSocket
	if err := os.MkdirAll(filepath.Dir(socket), 0755); err != nil {
		reportError(errorsChan, err)
		return
	}
	if _, err := os.Lstat(socket); err == nil {
		c, err := net.DialTimeout("unix", socket, 250*time.Millisecond)
		if err == nil {
			c.Close()
			reportError(errorsChan, fmt.Errorf("admin socket %s already active", socket))
			return
		}
		// Stale local socket, never delete arbitrary existing files.
		fi, err := os.Lstat(socket)
		if err != nil || fi.Mode()&os.ModeSocket == 0 {
			reportError(errorsChan, fmt.Errorf("admin_socket path %s exists and is not a socket", socket))
			return
		}
		if err = os.Remove(socket); err != nil {
			reportError(errorsChan, err)
			return
		}
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		reportError(errorsChan, err)
		return
	}
	defer func() { l.Close(); os.Remove(socket) }()
	_ = os.Chmod(socket, 0600)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.statusSnapshot())
	})
	mux.HandleFunc("/rescan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		g.rescan()
		w.WriteHeader(202)
		_, _ = io.WriteString(w, "scan queued\n")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err = srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		reportError(errorsChan, err)
	}
}
func (g *Gateway) run(ctx context.Context, scanOnly bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChan := make(chan error, 64)
	for i := 0; i < g.cfg.Config.DiscoveryWorkers; i++ {
		go g.worker(ctx)
	}
	for i, s := range g.cfg.Sources {
		go g.sourceLoop(ctx, s, i, errorsChan)
	}
	if !scanOnly {
		for _, c := range g.cfg.Clients {
			go g.metadataLoop(ctx, c, errorsChan)
			go g.clientLoop(ctx, c, errorsChan)
		}
		go g.adminLoop(ctx, errorsChan)
	}
	evictTicker := time.NewTicker(time.Minute)
	defer evictTicker.Stop()
	log.Printf("wsd-gateway %s: sources=%d clients=%d max_devices=%d scan_only=%t",
		version, len(g.cfg.Sources), len(g.cfg.Clients), g.cfg.Config.MaxDevices, scanOnly)
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errorsChan:
			return err
		case <-evictTicker.C:
			if n := g.reg.evict(); n > 0 {
				log.Printf("expired %d devices", n)
			}
		}
	}
}
