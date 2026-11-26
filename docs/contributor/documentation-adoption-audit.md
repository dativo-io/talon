# Documentation adoption truth audit — v1.17.0

Scope: release 410f1015a621326e722ebfb0fb9e84adf2a6a6dc plus approved documentation errata from #609 and #610. This is a documentation-only review, not a new release or runtime change.

| Defect | Correction | Grounding |
|---|---|---|
| Evidence demo unauthenticated request | Authenticated use-case request; same installation and signing key; tamper a copy | authentication-and-key-scopes; audit CLI implementation |
| Action proof stale status | Release-matched HTTP scope and shared MCP spine | Action Gateway reference; release pilot acceptance |
| Budget guide unsafe secret and non-deterministic expected outcome | stdin; currency; verified effective cap and independent count | configuration; provider registry; budget tests |
| Onboarding precedence | distinguish positive budget defaults from binding ceilings; keep actual CLI sample | configuration precedence; registration output remains a product wording gap |
| Session target mistaken for current API | current store statuses/source; target explicitly labelled | internal/session/store.go |
| Incident response | native controls vs external workload; verify activation; no blind replay | operate AI use cases; Action Gateway; limitations |
| Cookbook legacy recipes | distinguish native planning and removed native loop from governed actions | control-plane boundaries; limitations |
| Streaming contradictions | conditional delivery and no universal latency guarantee | configuration response actions; request lifecycle |
| Benchmarks stale retry status | shipped but not measured | limitations; configuration |
| Architecture status and config precedence | shipped MCP and console; field-specific merge | Action Gateway; console; configuration |

Remaining work: complete route-by-route semantic and executable validation, including legacy recipes, example-specific client versions, and incident controls in each supported boundary. The targeted regression script only protects the named defects; it cannot prove all claims or examples. The 20-question score and five journeys require re-evaluation after publication, not a claim of improvement from text edits alone. No change to runtime behavior is proposed. The registration CLI's tighten-only output is a product wording follow-up, not silently rewritten in the quoted output.

A targeted pattern scan covered all 72 website-mapped product documents. Additional findings: positional secret values in integration/primer/CI/native guides and configuration reference; obsolete `gateway.mode` in the local scanner walkthrough; unpinned clone instructions in two tutorials. Semantic-enrichment `mode` is a different supported field, not a removed gateway setting. This scan is not full semantic review or runtime execution. The release-notes history is retained. Further examples need boundary and fixture-level review in later commits before closing Step 1.
