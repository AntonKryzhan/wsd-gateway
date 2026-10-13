package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `wsd-gateway %s — automatic IPv4 WS-Discovery metadata gateway

Usage:
  wsd-gateway -config /path/config.json <command>
Commands:
  init         print editable example JSON configuration
  interfaces   list detected local IPv4 interface addresses
  check        validate configuration, interfaces and static devices
  scan         actively discover devices from source networks (no proxy/HTTP)
  run          run multi-interface WSD + HTTP metadata gateway
  status       list learned devices and counters from local UNIX admin socket
  rescan       request an immediate source scan through local admin socket
  version      show version
  help         show help

Flags:
  -config FILE       JSON config path (default /usr/local/etc/wsd-gateway.json)
  -scan-duration D   how long 'scan' runs (default 15s)
  -json              machine-readable status output
`, version)
}
func unixControl(socket, method, path string) ([]byte, error) {
	tr := &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.DialTimeout("unix", socket, 2*time.Second)
	}}
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	req, err := http.NewRequest(method, "http://unix"+path, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("management request: HTTP %d: %s", res.StatusCode, body)
	}
	return body, nil
}

// Accept flags either before or after the one-word subcommand (e.g.:
// `wsd-gateway scan -scan-duration 30s`).
func commandToEnd(args []string) []string {
	commands := map[string]bool{"run": true, "scan": true, "check": true, "status": true, "rescan": true, "interfaces": true, "init": true, "help": true, "version": true}
	for i, a := range args {
		if commands[a] {
			out := append([]string{}, args[:i]...)
			out = append(out, args[i+1:]...)
			return append(out, a)
		}
	}
	return args
}

func mainRun(args []string) error {
	args = commandToEnd(args)
	fs := flag.NewFlagSet("wsd-gateway", flag.ContinueOnError)
	confPath := fs.String("config", "/usr/local/etc/wsd-gateway.json", "config JSON path")
	scanD := fs.Duration("scan-duration", 15*time.Second, "scan duration")
	jsonOutput := fs.Bool("json", false, "JSON status")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmds := fs.Args()
	if len(cmds) != 1 {
		usage()
		return errors.New("provide exactly one command")
	}
	cmd := strings.ToLower(cmds[0])
	switch cmd {
	case "help", "--help", "-h":
		usage()
		return nil
	case "version":
		fmt.Println("wsd-gateway", version)
		return nil
	case "interfaces":
		lines, err := interfaceReport()
		if err != nil {
			return err
		}
		for _, s := range lines {
			fmt.Println(s)
		}
		return nil
	case "init":
		c := defaultConfig()
		c.Sources = []IfaceConfig{{Name: "SOURCE_NIC"}}
		c.Clients = []IfaceConfig{{Name: "CLIENT_NIC"}}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	}
	c, err := readConfig(*confPath)
	if err != nil {
		return err
	}
	if cmd == "status" || cmd == "rescan" {
		path := "/status"
		method := "GET"
		if cmd == "rescan" {
			path = "/rescan"
			method = "POST"
		}
		bytes, err := unixControl(c.AdminSocket, method, path)
		if err != nil {
			return err
		}
		if cmd == "status" && !*jsonOutput {
			var v struct {
				Version string            `json:"version"`
				Devices []Device          `json:"devices"`
				Stats   map[string]uint64 `json:"stats"`
			}
			if err := json.Unmarshal(bytes, &v); err != nil {
				return err
			}
			fmt.Printf("wsd-gateway %s: %d devices\n", v.Version, len(v.Devices))
			for _, d := range v.Devices {
				kind := "dynamic"
				if d.Static {
					kind = "static"
				}
				fmt.Printf("  %-40s  %-16s  %-15s  %s\n", d.UUID, d.IP, d.Origin, kind)
			}
			for k, n := range v.Stats {
				fmt.Printf("  %-18s %d\n", k, n)
			}
		} else {
			fmt.Print(string(bytes))
		}
		return nil
	}
	rt, err := validateConfig(c)
	if err != nil {
		return err
	}
	if cmd == "check" {
		fmt.Printf("CONFIG OK: %d source, %d client interfaces; HTTP %d; max_devices %d\n",
			len(rt.Sources), len(rt.Clients), c.HTTPPort, c.MaxDevices)
		for _, ep := range append(append([]Endpoint{}, rt.Sources...), rt.Clients...) {
			fmt.Printf("  %s: %s / %s allow=", ep.Name, ep.IP, ep.Net)
			for _, net := range ep.Network {
				fmt.Printf("%s ", net)
			}
			fmt.Println()
		}
		return nil
	}
	if cmd != "run" && cmd != "scan" {
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
	g, err := newGateway(rt)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if cmd == "scan" {
		if *scanD < time.Second {
			return errors.New("scan-duration must be at least 1s")
		}
		ctx, cancel := context.WithTimeout(ctx, *scanD)
		defer cancel()
		log.Printf("scan mode: discovering for %s; no WSD listener or HTTP port will be opened", *scanD)
		err := g.run(ctx, true)
		if err != nil {
			return err
		}
		list := g.reg.snapshot()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"devices": list, "count": len(list)})
	}
	if filepath.Clean(c.AdminSocket) == "/" {
		return errors.New("unsafe admin socket path")
	}
	return g.run(ctx, false)
}
func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	if err := mainRun(os.Args[1:]); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}
