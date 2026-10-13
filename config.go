package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// No network/subnet/hostname is compiled into the program. Interfaces are
// named in the deployment file; IPv4 addresses and directly attached networks
// can be inferred from the operating system.
type Config struct {
	Sources              []IfaceConfig  `json:"sources"`
	Clients              []IfaceConfig  `json:"clients"`
	HTTPPort             int            `json:"http_port"`
	AdminSocket          string         `json:"admin_socket"`
	ProbeInterval        string         `json:"probe_interval"`
	DeviceTTL            string         `json:"device_ttl"`
	MaxDevices           int            `json:"max_devices"`
	MaxResponsesPerProbe int            `json:"max_responses_per_probe"`
	DiscoveryWorkers     int            `json:"discovery_workers"`
	HTTPConcurrency      int            `json:"http_concurrency"`
	AllowedMetadataPorts []int          `json:"allowed_metadata_ports"`
	VerifyMetadata       bool           `json:"verify_metadata"`
	StaticDevices        []StaticDevice `json:"static_devices,omitempty"`
}
type IfaceConfig struct {
	Name         string   `json:"name"`
	IPv4         string   `json:"ipv4,omitempty"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}
type StaticDevice struct {
	Name            string `json:"name"`
	UUID            string `json:"uuid"`
	Upstream        string `json:"upstream"`
	Path            string `json:"path"`
	Types           string `json:"types,omitempty"`
	MetadataVersion int    `json:"metadata_version,omitempty"`
}
type Endpoint struct {
	Name    string
	IP      net.IP
	Net     *net.IPNet
	Network []*net.IPNet
	Iface   *net.Interface
}
type RuntimeConfig struct {
	Config        Config
	Sources       []Endpoint
	Clients       []Endpoint
	ProbeInterval time.Duration
	DeviceTTL     time.Duration
	AllowedPorts  map[int]bool
}

func defaultConfig() Config {
	return Config{
		HTTPPort: 15357, AdminSocket: "/var/run/wsd-gateway.sock",
		ProbeInterval: "60s", DeviceTTL: "15m", MaxDevices: 20000,
		MaxResponsesPerProbe: 128, DiscoveryWorkers: 16, HTTPConcurrency: 256,
		AllowedMetadataPorts: []int{5357}, VerifyMetadata: true,
	}
}
func readConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	var c Config
	if err = d.Decode(&c); err != nil {
		return c, fmt.Errorf("config JSON: %w", err)
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("config must contain exactly one JSON object")
	}
	return c, nil
}
func selectIPv4(iface *net.Interface, preferred string) (net.IP, *net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	var ips []net.IP
	var nets []*net.IPNet
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsMulticast() {
			continue
		}
		ips = append(ips, append(net.IP(nil), ip...))
		nets = append(nets, n)
	}
	if preferred != "" {
		target := net.ParseIP(preferred).To4()
		if target == nil {
			return nil, nil, fmt.Errorf("invalid IPv4 %q", preferred)
		}
		for i, p := range ips {
			if p.Equal(target) {
				return p, nets[i], nil
			}
		}
		return nil, nil, fmt.Errorf("IP %s is not assigned to interface %s", preferred, iface.Name)
	}
	if len(ips) != 1 {
		return nil, nil, fmt.Errorf("interface %s has %d IPv4 addresses; set ipv4 explicitly", iface.Name, len(ips))
	}
	return ips[0], nets[0], nil
}
func netRules(vals []string, inherited *net.IPNet) ([]*net.IPNet, error) {
	if len(vals) == 0 {
		return []*net.IPNet{inherited}, nil
	}
	if len(vals) > 256 {
		return nil, errors.New("too many allow CIDRs")
	}
	var out []*net.IPNet
	for _, s := range vals {
		ip, n, err := net.ParseCIDR(s)
		if err != nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 CIDR %q", s)
		}
		if !ip.Equal(n.IP) {
			return nil, fmt.Errorf("use network address in CIDR %q", s)
		}
		out = append(out, n)
	}
	return out, nil
}
func prepareIface(spec IfaceConfig) (Endpoint, error) {
	if spec.Name == "" {
		return Endpoint{}, errors.New("empty interface name")
	}
	iface, err := net.InterfaceByName(spec.Name)
	if err != nil {
		return Endpoint{}, err
	}
	if iface.Flags&net.FlagUp == 0 {
		return Endpoint{}, fmt.Errorf("%s is down", spec.Name)
	}
	ip, n, err := selectIPv4(iface, spec.IPv4)
	if err != nil {
		return Endpoint{}, err
	}
	rules, err := netRules(spec.AllowedCIDRs, n)
	if err != nil {
		return Endpoint{}, err
	}
	baseOnes, _ := n.Mask.Size()
	for _, rule := range rules {
		ruleOnes, _ := rule.Mask.Size()
		if ruleOnes < baseOnes || !n.Contains(rule.IP) {
			return Endpoint{}, fmt.Errorf("allowed CIDR %s must be contained in %s on interface %s", rule, n, spec.Name)
		}
	}
	return Endpoint{Name: spec.Name, IP: ip, Net: n, Network: rules, Iface: iface}, nil
}
func anyAllowed(ip net.IP, rules []*net.IPNet) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	for _, r := range rules {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
func validateConfig(c Config) (*RuntimeConfig, error) {
	if len(c.Sources) == 0 || len(c.Clients) == 0 {
		return nil, errors.New("at least one source and one client interface required")
	}
	if len(c.Sources) > 16 || len(c.Clients) > 16 {
		return nil, errors.New("up to 16 source and 16 client interfaces")
	}
	if c.HTTPPort < 1024 || c.HTTPPort > 65535 {
		return nil, errors.New("http_port must be 1024..65535")
	}
	if c.AdminSocket == "" || !strings.HasPrefix(c.AdminSocket, "/") {
		return nil, errors.New("admin_socket must be an absolute local path")
	}
	if c.MaxDevices < 1 || c.MaxDevices > 200000 {
		return nil, errors.New("max_devices must be 1..200000")
	}
	if c.MaxResponsesPerProbe < 1 || c.MaxResponsesPerProbe > 20000 {
		return nil, errors.New("max_responses_per_probe must be 1..20000")
	}
	if c.DiscoveryWorkers < 1 || c.DiscoveryWorkers > 128 {
		return nil, errors.New("discovery_workers must be 1..128")
	}
	if c.HTTPConcurrency < 1 || c.HTTPConcurrency > 8192 {
		return nil, errors.New("http_concurrency must be 1..8192")
	}
	probeInterval, err := time.ParseDuration(c.ProbeInterval)
	if err != nil || probeInterval < 10*time.Second {
		return nil, errors.New("probe_interval must be >= 10s")
	}
	ttl, err := time.ParseDuration(c.DeviceTTL)
	if err != nil || ttl < probeInterval*2 {
		return nil, errors.New("device_ttl must be >= 2x probe_interval")
	}
	if len(c.AllowedMetadataPorts) == 0 || len(c.AllowedMetadataPorts) > 32 {
		return nil, errors.New("allowed_metadata_ports required (1..32)")
	}
	ports := make(map[int]bool)
	for _, p := range c.AllowedMetadataPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid metadata port %d", p)
		}
		ports[p] = true
	}
	var src, dst []Endpoint
	used := map[string]bool{}
	for _, s := range c.Sources {
		ep, err := prepareIface(s)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s.Name, err)
		}
		if used[s.Name] {
			return nil, fmt.Errorf("duplicated interface %s", s.Name)
		}
		used[s.Name] = true
		src = append(src, ep)
	}
	for _, s := range c.Clients {
		ep, err := prepareIface(s)
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", s.Name, err)
		}
		if used[s.Name] {
			return nil, fmt.Errorf("interface %s cannot simultaneously be source and client", s.Name)
		}
		used[s.Name] = true
		dst = append(dst, ep)
	}
	// Refuse dangerous unintentionally overlapping source/client networks.
	for _, a := range src {
		for _, b := range dst {
			if a.Net.Contains(b.IP) || b.Net.Contains(a.IP) {
				return nil, fmt.Errorf("source %s and client %s directly attached networks overlap", a.Name, b.Name)
			}
		}
	}
	seen := map[string]bool{}
	for _, d := range c.StaticDevices {
		if !validUUID(d.UUID) {
			return nil, fmt.Errorf("invalid static UUID %s", d.UUID)
		}
		if seen[strings.ToLower(d.UUID)] {
			return nil, fmt.Errorf("duplicated static UUID %s", d.UUID)
		}
		seen[strings.ToLower(d.UUID)] = true
		host, port, err := net.SplitHostPort(d.Upstream)
		if err != nil || net.ParseIP(host).To4() == nil {
			return nil, fmt.Errorf("static upstream must be IPv4:port: %s", d.Upstream)
		}
		pn, _ := strconv.Atoi(port)
		if !ports[pn] {
			return nil, fmt.Errorf("static device port %d not allowed", pn)
		}
		if _, ok := validMetaPath(d.Path, d.UUID); !ok {
			return nil, fmt.Errorf("invalid metadata path for %s", d.UUID)
		}
		if d.MetadataVersion < 0 {
			return nil, errors.New("metadata_version cannot be negative")
		}
		if d.Types != "" && len(typesFromConfigured(d.Types)) == 0 {
			return nil, fmt.Errorf("unsupported static device types %q", d.Types)
		}
		inSource := false
		for _, s := range src {
			if anyAllowed(net.ParseIP(host), s.Network) {
				inSource = true
				break
			}
		}
		if !inSource {
			return nil, fmt.Errorf("static device %s outside configured source networks", d.Name)
		}
	}
	return &RuntimeConfig{Config: c, Sources: src, Clients: dst, ProbeInterval: probeInterval, DeviceTTL: ttl, AllowedPorts: ports}, nil
}
func interfaceReport() ([]string, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, i := range all {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		var v4 []string
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				v4 = append(v4, n.String())
			}
		}
		if len(v4) > 0 {
			lines = append(lines, fmt.Sprintf("%-16s %s", i.Name, strings.Join(v4, ", ")))
		}
	}
	sort.Strings(lines)
	return lines, nil
}
