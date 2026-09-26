# MCP subsystem invariants

These rules apply when changing `internal/mcp/**` or MCP-specific adapters/tests.

Before changing wire behavior, read the current MCP issues linked from #265. Do not infer the target protocol from legacy code.

Current direction is the MCP 2026-07-28 contract; backwards compatibility with older MCP protocol behavior is not a default requirement.

Keep these boundaries explicit:

- protocol parsing/validation is separate from Talon business authorization;
- client-provided MCP metadata is untrusted input, not business authority;
- where request metadata mirrors body fields, validate the mirror against the parsed body before business dispatch;
- protocol errors remain protocol errors; Talon policy/authorization denials remain Talon governance decisions;
- transport/session/task/JSON-RPC identifiers are not business operation identity and are never bearer authorization;
- MCP client/user input cannot create authenticated reviewer authority;
- discovery/proposal does not create approval or dispatch;
- Talon may only claim prevention for calls/actions actually routed through an enforceable boundary.

Do not preserve removed handshake/session semantics merely because tests or helpers still mention them. Update conformance fixtures/tests to the active protocol contract.

For preventive MCP tests, prove zero upstream dispatch on denied/invalid paths.
