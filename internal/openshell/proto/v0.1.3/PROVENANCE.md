# Pinned OpenShell supervisor-middleware contract

Upstream: https://github.com/NVIDIA/OpenShell, tag **v0.1.3** (released 2026-10-09).
Files are byte-for-byte copies of the tagged sources; nothing is edited here.

| File | Upstream path | sha256 |
|---|---|---|
| `supervisor_middleware.proto` | `proto/supervisor_middleware.proto` | `bee96ac940303d8a7530e6e2283a98077bb428a05ef610b51d018ea18377bebd` |
| `extension.proto` | `proto/extension.proto` | `60f28ee9dc846d41152f4db7e82a439c78d024786efaceb464900d1d1ad129ad` |

Both files are identical to the v0.1.2 tag: the middleware wire contract did
not change between the two releases (protocol 1.0, same bindings, same
`PeerMetadata`, same `HttpResponsePreReturn` and WebSocket services). What
changed for Talon is behavioural: the gateway's extension negotiation requires
the extension's `protocol_version` and `openshell.supervisor-middleware.contract`
capability, which Talon now advertises and validates reciprocally.

Regenerate Go types with `scripts/openshell-proto-gen.sh` (buf as a Go tool);
verify the pins with `sha256sum internal/openshell/proto/v0.1.3/*.proto`.
