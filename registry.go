package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type Device struct {
	UUID            string    `json:"uuid"`
	Name            string    `json:"name"`
	IP              string    `json:"ip"`
	Port            int       `json:"port"`
	Path            string    `json:"path"`
	Origin          string    `json:"origin"`
	Types           []QName   `json:"types"`
	MetadataVersion int       `json:"metadata_version"`
	LastSeen        time.Time `json:"last_seen"`
	Static          bool      `json:"static"`
}
type Registry struct {
	mu              sync.RWMutex
	items           map[string]Device
	pending         map[string]bool
	max             int
	ttl             time.Duration
	cached          []Device
	cacheTime       time.Time
	generation      uint64
	cacheGeneration uint64
}

func newRegistry(c *RuntimeConfig) (*Registry, error) {
	r := &Registry{items: make(map[string]Device), pending: make(map[string]bool), max: c.Config.MaxDevices, ttl: c.DeviceTTL}
	for _, d := range c.Config.StaticDevices {
		host, p, err := net.SplitHostPort(d.Upstream)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		origin := ""
		for _, s := range c.Sources {
			if anyAllowed(ip, s.Network) {
				origin = s.Name
				break
			}
		}
		if origin == "" {
			return nil, fmt.Errorf("static device %s (%s) not on allowed source network", d.Name, ip)
		}
		var port int
		fmt.Sscanf(p, "%d", &port)
		types := []QName{{nsDevice, "Device"}, {nsComputer, "Computer"}}
		if d.Types != "" {
			types = typesFromConfigured(d.Types)
		}
		v := d.MetadataVersion
		if v == 0 {
			v = 1
		}
		r.items[strings.ToLower(d.UUID)] = Device{
			UUID: strings.ToLower(d.UUID), Name: d.Name, IP: ip.String(), Port: port, Path: d.Path, Origin: origin, Types: types,
			MetadataVersion: v, LastSeen: time.Now(), Static: true,
		}
	}
	if len(r.items) > r.max {
		return nil, fmt.Errorf("static devices count greater than max_devices")
	}
	return r, nil
}
func typesFromConfigured(s string) []QName {
	out := []QName{}
	for _, t := range strings.Fields(s) {
		switch t {
		case "wsdp:Device":
			out = append(out, QName{nsDevice, "Device"})
		case "pub:Computer":
			out = append(out, QName{nsComputer, "Computer"})
		}
	}
	return out
}
func (r *Registry) begin(id, ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.items[id]; ok {
		if d.Static {
			return false
		}
		if d.IP == ip {
			d.LastSeen = time.Now()
			r.items[id] = d
			return false
		}
		// UUID collision / impersonation: never silently swap the upstream.
		return false
	}
	if r.pending[id] || len(r.items)+len(r.pending) >= r.max {
		return false
	}
	r.pending[id] = true
	return true
}
func (r *Registry) finish(d Device, verified bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, strings.ToLower(d.UUID))
	if verified {
		if _, ok := r.items[strings.ToLower(d.UUID)]; !ok && len(r.items) < r.max {
			r.items[strings.ToLower(d.UUID)] = d
			r.generation++
		}
	}
}
func (r *Registry) get(id string) (Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.items[strings.ToLower(id)]
	if ok && !d.Static && time.Since(d.LastSeen) > r.ttl {
		return Device{}, false
	}
	return d, ok
}
func (r *Registry) snapshot() []Device {
	r.mu.RLock()
	if r.cached != nil && r.cacheGeneration == r.generation && time.Since(r.cacheTime) < 5*time.Second {
		result := r.cached
		r.mu.RUnlock()
		return result // immutable; replaced, never mutated
	}
	r.mu.RUnlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cached != nil && r.cacheGeneration == r.generation && time.Since(r.cacheTime) < 5*time.Second {
		return r.cached
	}
	out := make([]Device, 0, len(r.items))
	for _, d := range r.items {
		if !d.Static && time.Since(d.LastSeen) > r.ttl {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UUID < out[j].UUID })
	r.cached = out
	r.cacheTime = time.Now()
	r.cacheGeneration = r.generation
	return out
}
func (r *Registry) evict() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	deleted := 0
	now := time.Now()
	for k, v := range r.items {
		if !v.Static && now.Sub(v.LastSeen) > r.ttl {
			delete(r.items, k)
			deleted++
			r.generation++
		}
	}
	return deleted
}
