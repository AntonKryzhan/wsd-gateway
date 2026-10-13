# Security policy / threat model

This is an **alpha** transport gateway, not a WS-Discovery authentication framework.

**Trust boundaries**
1. A WSD device can send unauthenticated UDP/XML discovery responses. Restrict source interfaces, `allowed_cidrs` and `allowed_metadata_ports` to admin-controlled segments.
2. Only IPs included in a source interface's allowlist can become metadata upstream endpoints; the discovered `XAddr` hostname is intentionally ignored. The actual HTTP connection goes to the **observed UDP source IP** at an allowed metadata port. Source devices can still be malicious or compromised.
3. No user-requested target URL, redirect or proxy environment variable is used. An untrusted client cannot choose an upstream target. Client HTTP is POST-only, limited to WS-Transfer Get, 64 KiB request payload / 2 MiB response.
4. Local management uses a UNIX socket at 0600 (no network management interface). Protect and back up the configuration file. Physical/privileged shell users retain full control.
5. XML parser caps at 32 KiB, element depth 32, bounded number of types, and UDP queue/verification worker/HTTP concurrency caps.
6. Unauthenticated WSD can be spoofed even with `verify_metadata=true`: that setting verifies response availability and format, **not the cryptographic identity** of the device.
7. No TLS, HTTPS metadata, WS-Discovery signatures, IPv6, host-origin authentication or tenant isolation are implemented. Do not expose this gateway directly to the public Internet.

**Operational guidance**
- Disable source-to-client packet reflection if it creates duplicate responses (do so under an approved change procedure).
- Keep the server firewall policy closed except for the designated VLANs and metadata port.
- Deploy only on trusted routed networks, with network-level ACLs.
- Review logs for repeated failed metadata verifications; rate-limit or block abusive hosts at the network edge.
- Test on a separate interface or use `scan` first, and keep a backup of the working old service.
- Do not publish private server names/IPs/UUIDs from operational logs or deployment configs.
- For production-grade Internet-facing deployments, add authenticated discovery, tenant isolation and sustained load/fuzz testing before use.

To report a security issue, open a private security advisory in the project repository once published. Do not publicly disclose details of an unpatched exploit.
