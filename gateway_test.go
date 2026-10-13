package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const hostnameFixture = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"><soap:Header><wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action><wsa:MessageID>urn:uuid:6e36e8df-faf5-454c-ac2d-ce36aee85d65</wsa:MessageID><wsa:RelatesTo>urn:uuid:6d23fd0a-7ca2-4a63-8ad3-bac8c64ff264</wsa:RelatesTo><wsd:AppSequence InstanceId="1789214739" SequenceId="urn:uuid:9cd2f138-e0f8-48d3-b871-4563b2594c42" MessageNumber="107944"/></soap:Header><soap:Body><wsd:ProbeMatches><wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device pub:Computer</wsd:Types><wsd:XAddrs>http://EXAMPLE-HOST:5357/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee</wsd:XAddrs><wsd:MetadataVersion>2</wsd:MetadataVersion></wsd:ProbeMatch></wsd:ProbeMatches></soap:Body></soap:Envelope>`

const ipv4Fixture = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action><wsa:MessageID>urn:uuid:74f0916e-b8da-4326-a3e0-0544a0ec7f91</wsa:MessageID></soap:Header><soap:Body><wsd:ProbeMatches><wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:bbbbbbbb-cccc-4ddd-8eee-ffffffffffff</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device pub:Computer</wsd:Types><wsd:XAddrs>http://192.0.2.74:5357/bbbbbbbb-cccc-4ddd-8eee-ffffffffffff/</wsd:XAddrs><wsd:MetadataVersion>4</wsd:MetadataVersion></wsd:ProbeMatch></wsd:ProbeMatches></soap:Body></soap:Envelope>`

func TestSanitizedHostnameAndIPv4Fixtures(t *testing.T) {
	for _, tc := range []struct {
		raw, id, path string
		version       int
	}{
		{hostnameFixture, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", 2},
		{ipv4Fixture, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "/bbbbbbbb-cccc-4ddd-8eee-ffffffffffff/", 4},
	} {
		m, err := parseWSD([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		if m.Action != nsWSD+"/ProbeMatches" || m.Target != "urn:uuid:"+tc.id || m.MetadataVersion != tc.version {
			t.Fatalf("%+v", m)
		}
		path, port, ok := parseXAddr(m, net.ParseIP("192.0.2.9"), map[int]bool{5357: true})
		if !ok || path != tc.path || port != 5357 {
			t.Fatalf("routing %q %d %v", path, port, ok)
		}
		if len(m.Types) != 2 || m.Types[1] != (QName{nsComputer, "Computer"}) {
			t.Fatalf("types %v", m.Types)
		}
	}
}
func TestProbeMatchesAndResolve(t *testing.T) {
	d := Device{UUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Types: []QName{{nsDevice, "Device"}, {nsComputer, "Computer"}}, MetadataVersion: 2}
	p := makeProbe()
	req, e := parseWSD(p)
	if e != nil {
		t.Fatal(e)
	}
	if req.Action != nsWSD+"/Probe" || !matchesProbe(req, d) {
		t.Fatalf("unexpected probe %+v", req)
	}
	for _, kind := range []string{"ProbeMatches", "ResolveMatches"} {
		raw := writeReply(kind, req.MessageID, "abc", "12345", 11, d, "http://192.0.2.1:15357/"+d.UUID+"/")
		m, err := parseWSD(raw)
		if err != nil {
			t.Fatal(err)
		}
		if m.Action != nsWSD+"/"+kind || m.RelatesTo != req.MessageID || m.Target != "urn:uuid:"+d.UUID || m.MetadataVersion != 2 {
			t.Fatalf("%+v", m)
		}
		if len(m.Types) != 2 || m.Types[1].URI != nsComputer {
			t.Fatalf("bad types %+v", m.Types)
		}
	}
}
func TestRejectBadXAddrs(t *testing.T) {
	m, err := parseWSD([]byte(hostnameFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"file:///etc/passwd", "http://EXAMPLE-HOST:5356/" + strings.TrimPrefix(m.Target, "urn:uuid:"),
		"http://EXAMPLE-HOST:5357/../../etc/passwd",
		"http://EXAMPLE-HOST:5357/../../etc/passwd",
		"http://EXAMPLE-HOST:5357/" + strings.TrimPrefix(m.Target, "urn:uuid:") + "?foo=bar",
	} {
		m.XAddrs = raw
		if _, _, ok := parseXAddr(m, net.ParseIP("192.0.2.9"), map[int]bool{5357: true}); ok {
			t.Fatalf("accepted %q", raw)
		}
	}
}
func TestRegistryScaleAndExpiry(t *testing.T) {
	cfg := &RuntimeConfig{Config: Config{MaxDevices: 20000}, DeviceTTL: time.Minute}
	r, err := newRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
		if !r.begin(id, "192.0.2.10") {
			t.Fatalf("begin failed %d", i)
		}
		r.finish(Device{UUID: id, IP: "192.0.2.10", LastSeen: time.Now(), Types: []QName{{nsDevice, "Device"}}}, true)
	}
	if got := len(r.snapshot()); got != 10000 {
		t.Fatalf("count %d", got)
	}
}
func TestMetadataProxyRouteAndAllowlist(t *testing.T) {
	id := "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	gotPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		if !bytes.Contains(b, []byte(actionGet)) {
			t.Errorf("missing Get")
		}
		w.Header().Set("Content-Type", "application/soap+xml")
		fmt.Fprint(w, "<Envelope><GetResponse>good</GetResponse></Envelope>")
	}))
	defer server.Close()
	host, prt, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	port, _ := strconv.Atoi(prt)
	_, netw, _ := net.ParseCIDR("127.0.0.0/8")
	c := &RuntimeConfig{Config: Config{HTTPConcurrency: 10, MaxDevices: 20000}, AllowedPorts: map[int]bool{port: true}, DeviceTTL: time.Minute}
	g, e := newGateway(c)
	if e != nil {
		t.Fatal(e)
	}
	g.reg.finish(Device{UUID: id, IP: host, Port: port, Path: "/" + id, LastSeen: time.Now()}, true)
	ep := Endpoint{Network: []*net.IPNet{netw}}
	req := httptest.NewRequest("POST", "http://127.0.0.1:15357/"+id+"/", bytes.NewReader(makeMetadataGet(id)))
	req.RemoteAddr = "127.0.0.15:50000"
	w := httptest.NewRecorder()
	g.httpHandler(ep).ServeHTTP(w, req)
	if w.Code != 200 || gotPath != "/"+id {
		t.Fatalf("code=%d path=%q body=%s", w.Code, gotPath, w.Body)
	}
	denied := httptest.NewRequest("POST", "http://127.0.0.1:15357/"+id+"/", bytes.NewReader(makeMetadataGet(id)))
	denied.RemoteAddr = "192.0.2.10:50100"
	w2 := httptest.NewRecorder()
	g.httpHandler(ep).ServeHTTP(w2, denied)
	if w2.Code != 403 {
		t.Fatalf("expected 403, got %d", w2.Code)
	}
}
func TestAutomaticObservedSourceIP(t *testing.T) {
	_, allowed, _ := net.ParseCIDR("192.0.2.0/24")
	c := &RuntimeConfig{Config: Config{MaxDevices: 20000, DiscoveryWorkers: 1, AllowedMetadataPorts: []int{5357}}, AllowedPorts: map[int]bool{5357: true}, DeviceTTL: time.Minute}
	g, err := newGateway(c)
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{Name: "lan2", IP: net.ParseIP("192.0.2.1"), Network: []*net.IPNet{allowed}}
	g.handleSource(ep, &net.UDPAddr{IP: net.ParseIP("192.0.2.19"), Port: 3702}, []byte(hostnameFixture))
	select {
	case item := <-g.work:
		if item.device.IP != "192.0.2.19" || item.device.Path != "/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" {
			t.Fatalf("%+v", item.device)
		}
	default:
		t.Fatal("not discovered")
	}
	g.handleSource(ep, &net.UDPAddr{IP: net.ParseIP("192.0.3.19"), Port: 3702}, []byte(hostnameFixture))
	select {
	case <-g.work:
		t.Fatal("accepted other source subnet")
	default:
	}
}
func TestStatusJSONSerializesTenThousand(t *testing.T) {
	cfg := &RuntimeConfig{Config: Config{MaxDevices: 20000}, DeviceTTL: time.Minute}
	g, e := newGateway(cfg)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
		g.reg.finish(Device{UUID: id, LastSeen: time.Now()}, true)
	}
	b, e := json.Marshal(g.statusSnapshot())
	if e != nil {
		t.Fatal(e)
	}
	if len(b) < 100000 {
		t.Fatalf("unexpected bytes %d", len(b))
	}
}
func TestTypeFilteringAndCIDR(t *testing.T) {
	d := Device{Types: []QName{{nsDevice, "Device"}, {nsComputer, "Computer"}}}
	if matchesProbe(WSDMessage{Action: nsWSD + "/Probe", Types: []QName{{"urn:printer", "Printer"}}}, d) {
		t.Fatal("matched printer")
	}
	if !matchesProbe(WSDMessage{Action: nsWSD + "/Probe", Types: []QName{{nsDevice, "Device"}}}, d) {
		t.Fatal("failed Device")
	}
	_, n, _ := net.ParseCIDR("198.51.100.0/23")
	if !anyAllowed(net.ParseIP("198.51.101.24"), []*net.IPNet{n}) || anyAllowed(net.ParseIP("203.0.113.1"), []*net.IPNet{n}) {
		t.Fatal("CIDR")
	}
}
func TestUserConfigDecoding(t *testing.T) {
	f := t.TempDir() + "/c.json"
	if err := os.WriteFile(f, []byte(`{"sources":[{"name":"uplink0","ipv4":"192.0.2.1"}],"clients":[{"name":"lan1"}],"http_port":15357,"admin_socket":"/tmp/gw.sock","probe_interval":"60s","device_ttl":"15m","max_devices":20000,"max_responses_per_probe":128,"discovery_workers":16,"http_concurrency":256,"allowed_metadata_ports":[5357],"verify_metadata":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := readConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxDevices != 20000 || c.Sources[0].IPv4 != "192.0.2.1" {
		t.Fatal("bad config")
	}
}
func BenchmarkRegistrySnapshot10k(b *testing.B) {
	c := &RuntimeConfig{Config: Config{MaxDevices: 20000}, DeviceTTL: time.Minute}
	r, _ := newRegistry(c)
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
		r.finish(Device{UUID: id, LastSeen: time.Now()}, true)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.snapshot()
	}
}

var _ = context.Background

func TestCommandFlagsAfterSubcommand(t *testing.T) {
	got := commandToEnd([]string{"-config", "/tmp/conf.json", "scan", "-scan-duration", "20s"})
	if got[len(got)-1] != "scan" || got[2] != "-scan-duration" {
		t.Fatalf("bad args %#v", got)
	}
}
