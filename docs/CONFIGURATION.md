# Configuration reference

All configuration is UTF-8 JSON. JSON comments are not supported; use this document for explanations.

| Key | Type | Notes |
|---|---|---|
| `sources` | list | 1–16 objects `{name, ipv4?, allowed_cidrs?}` |
| `clients` | list | 1–16 objects `{name, ipv4?, allowed_cidrs?}` |
| `http_port` | int | TCP 1024–65535; separate bind on each client IPv4 |
| `admin_socket` | string | absolute UNIX socket path; mode 0600 |
| `probe_interval` | duration | e.g. `"60s"`; min 10 s |
| `device_ttl` | duration | e.g. `"15m"`; ≥ 2× probe interval |
| `max_devices` | int | 1..200000; prevent unbounded memory |
| `max_responses_per_probe` | int | 1..20000; limit WSD replies for each Windows Probe |
| `discovery_workers` | int | 1..128; parallel HTTP metadata validation |
| `http_concurrency` | int | 1..8192 per client HTTP listener |
| `allowed_metadata_ports` | list of integers | default `[5357]` |
| `verify_metadata` | bool | true recommended, authenticates reachability **not identity** |
| `static_devices` | list | optional migration seeds; fixed UUID, upstream, original path |

### Interface address inference

No `ipv4`? Then the NIC must have exactly **one** usable IPv4 address. That address and the directly attached subnet become the identity/allowlist. With alias addresses (e.g. a FreeBSD trunk holding two IPv4s) select one:

```json
{"name": "em0", "ipv4": "192.0.2.1", "allowed_cidrs": ["192.0.2.0/24"]}
```

For a second /23 client subnet on the *same physical NIC*, if the NIC carries separate IP aliases, create appropriate VLAN subinterfaces first and configure them individually. The gateway does not configure switches or interfaces.

### Metadata exposure

Only learned UUIDs resolve at `http://<client-vlan-IP>:<http_port>/<UUID>/`. HTTP POST must contain the WS-Transfer `Get` action, source IP must be permitted, size is capped at 64 KiB, response copy capped at 2 MiB. Upstream address is observed **source IP** of a verified WSD response, not client-controlled and not DNS-resolved from advertised XAddr. The upstream port must be allowlisted.

### Static migration seeds

```json
"static_devices": [
  {
    "name": "EXAMPLE-SERVER",
    "uuid": "12345678-1234-4234-8234-123456789abc",
    "upstream": "192.0.2.40:5357",
    "path": "/12345678-1234-4234-8234-123456789abc/",
    "types": "wsdp:Device pub:Computer",
    "metadata_version": 1
  }
]
```

Private deployment-specific files should never be committed to a public repository.

### Interactions with reflectors

Avoid publishing the same UUID simultaneously from multiple independent responders where possible. The gateway responds to local Windows searches and periodically queries remote devices on its configured **source** interfaces; a separate multicast reflector is not required for that pathway. It may coexist with existing Netflector rules but duplicates and routing feedback need site-level verification.

### FreeBSD deployment checklist

1. Transfer release binary and sanitized/edited configuration.
2. `wsd-gateway -config /path/to/config.json check`
3. `wsd-gateway -config /path/to/config.json scan -scan-duration 20s` — check that devices resolve before changing services.
4. Back up current `rc.d` and binary; plan rollback.
5. Stage rc script as `wsd_gateway`; don't enable it.
6. During maintenance, stop the previous WSD proxy **only**; leave Netflector and other services untouched.
7. `service wsd_gateway onestart`; inspect `status`, logs, and test Windows Explorer/SMB from several clients.
8. When stable: `sysrc wsd_gateway_enable=YES`. Consider disabling prior `ngs_wsd_proxy_enable` **after** successful migration.
9. Roll back by stopping `wsd_gateway` and starting your previous WSD service.

Do not restart the production gateway/router itself merely to test service startup.

### IPv4 firewall policy

Allow UDP 3702 multicast from WSD clients on designated client VLANs to the gateway, and UDP ProbeMatches from source devices back to the gateway's source socket; allow selected HTTP metadata TCP port from permitted client VLANs to gateway, and TCP 5357 (or explicitly configured metadata ports) from the gateway to source devices. Apply policy using your existing firewall deployment procedures; this program does not add rules.
