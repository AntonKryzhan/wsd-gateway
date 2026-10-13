# WSD Gateway

**Automatic multi-network WS-Discovery (IPv4) gateway for Windows Explorer network discovery.**

A Go-based, configurable WS-Discovery device discovery and metadata gateway. It makes WS-Discovery devices on designated **source networks** discoverable by hosts on different **client networks**. This is **not** a transparent multicast relay and does not forward SMB file traffic.

> **Release status: v0.4.0-alpha.1 / engineering preview.** The protocol parser, local HTTP forwarding, CIDR checks, registry scalability and cross-compilation have automated tests. It has **not** yet been validated with real FreeBSD VLAN traffic in this version. Keep your existing WSD discovery arrangement as rollback until field tests pass.

[Русская документация](README_RU.md) · [Configuration guide](docs/CONFIGURATION.md) · [Security notes](SECURITY.md)

## Why

Windows WSDAPI checks that a `ProbeMatches` / `ResolveMatches` XAddr is on the same subnet as the receiving adapter. Simply relaying UDP/3702 packets between VLANs can result in a computer visible to a sniffer but absent from Explorer. [Microsoft XAddr rules](https://learn.microsoft.com/en-us/windows/win32/wsdapi/xaddr-validation-rules).

WSD Gateway learns real devices automatically, advertises a **local client-side** XAddr, and forwards metadata requests to the actual source device.

```text
   source Ethernet/VLAN                     client Ethernet/VLAN
   multiple real WSD endpoints              Windows Explorer clients
   UDP ProbeMatches                          UDP Probe/Resolve
       │                                          │
       ▼                                          ▼
   +------------------------------------------------------+
   | WSD Gateway (FreeBSD / Linux)                        |
   | source scanner → bounded registry / UUID cache       |
   |   → WSD responder on each client interface           |
   |   → HTTP metadata proxy per client-side local IP     |
   +------------------------------------------------------+
            │                               │
    HTTP POST on discovered IP:port     local XAddr IP:http_port
```

### Automatic discovery without `tcpdump`

For each **source** interface, the gateway sends WSD Probe packets to `239.255.255.250:3702`, binds a UDP socket to that source interface's configured/detected IPv4, and receives unicast ProbeMatches. It learns:

- Endpoint UUID, device types and metadata version
- Actual response source IP (never resolves the XAddr's hostname)
- HTTP metadata port and path from XAddr
- Last seen time, metadata-reported computer name when available

By default it checks the metadata server with WS-Transfer Get before registering a device. After `device_ttl` without valid subsequent discovery it expires the entry. Addresses and subnet masks are **not hard-coded in the binary**.

### Operational controls

```sh
wsd-gateway interfaces
wsd-gateway -config /usr/local/etc/wsd-gateway.json check
wsd-gateway -config /usr/local/etc/wsd-gateway.json scan -scan-duration 20s
wsd-gateway -config /usr/local/etc/wsd-gateway.json run
wsd-gateway -config /usr/local/etc/wsd-gateway.json status
wsd-gateway -config /usr/local/etc/wsd-gateway.json rescan
wsd-gateway version
wsd-gateway init
```

`scan` starts only source discovery, not WSD advertisement, HTTP listener or management socket. This is suitable for a read-only proof of discovery while the previous working proxy remains active. It **does** send UDP multicast Probe messages and HTTP Get to discovered servers.

## Configuration

Copy [`configs/config.example.json`](configs/config.example.json), edit the **interface names** and optional network allowlists, then `check`.

```json
{
  "sources": [{"name": "SOURCE_INTERFACE"}],
  "clients": [{"name": "CLIENT_INTERFACE"}],
  "http_port": 15357,
  "admin_socket": "/var/run/wsd-gateway.sock",
  "probe_interval": "60s",
  "device_ttl": "15m",
  "max_devices": 20000,
  "max_responses_per_probe": 128,
  "discovery_workers": 16,
  "http_concurrency": 256,
  "allowed_metadata_ports": [5357],
  "verify_metadata": true,
  "static_devices": []
}
```

If a network interface has **exactly one IPv4 address**, the gateway detects it automatically and infers the directly attached CIDR. For aliases / multiple IP addresses, use `ipv4` explicitly. `allowed_cidrs` can explicitly restrict incoming sources or clients. There are **no default interfaces or open catch-all networks**.

`static_devices` is optional for a migration/known-important hosts; new WSD endpoints are still learned automatically.

## Build and service

Requires Go 1.22 or later; build/test on Go 1.23:

```sh
go test -race ./...
go vet ./...
make cross
```

Four outputs: FreeBSD/amd64, FreeBSD/arm64, Linux/amd64 and Linux/arm64. No third-party Go libraries and no Go runtime required on deployment host.

FreeBSD `rc.d` template: [`etc/rc.d/wsd_gateway`](etc/rc.d/wsd_gateway).
A non-disruptive staging script is available: [`scripts/stage-freebsd.sh`](scripts/stage-freebsd.sh). It **does not** stop, start or enable any service. For a production change, back up your existing service, validate the new config, run `scan`, then schedule a short port switchover and keep the old binary for rollback. Enable only after device visibility, shares and restarts are verified.

## Capacity

The code limits registration (`max_devices`), metadata-verification workers, HTTP concurrency and **WSD replies per individual Probe**. It batches/rotates response selection between distinct discovery MessageIDs and caches sorted registry snapshots. A unit test exercises **10,000 synthetic device registrations**. This is a data-structure test **not proof of 10,000 live devices or discovery clients in one production network**; actual maximums are constrained by UDP multicast traffic, OS socket buffers, device behavior, metadata throughput and Windows Explorer.

To prevent floods, the safe default is **128 devices advertised per Probe**. Consequently there is **no promise** that a Windows client will see every one of 20,000 registered devices. Scale by segmentation/allowlisting and load testing before raising the cap.

## Limitations

- IPv4 only. WS-Discovery 2005/04 profiles (Windows WSDAPI) supported; no WS-Discovery 1.1/IPv6 translation.
- HTTP metadata WS-Transfer Get. No transparent support for arbitrary WS-Discovery SOAP services, authenticated endpoints, HTTPS-only XAddrs or encrypted/signed discovery.
- Not a Layer-2 or generic multicast bridge, SMB proxy, WINS or mDNS service.
- `Scopes`-based filters and dynamic Hello/Bye announcement translation are not implemented in this preview. New devices appear when a client issues its next Probe/Resolve.
- Discovery assumes that source network devices respond to active local UDP multicast Probe and expose reachable HTTP metadata.
- Multiple gateways/reflectors publishing the same UUID may produce duplicate or conflicting responses. Plan migration carefully.
- If `static_devices` are used, their origin and path remain as configured until you edit and restart.
- The example FreeBSD service runs with the privileges of the service process. Harden privileges and firewall rules for production networks.

See [Security notes](SECURITY.md).

## License

MIT. This repository's examples do not contain real customer/school IP addresses, server names, MACs or UUIDs.
