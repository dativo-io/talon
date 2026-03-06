# Governed Semantic Cache

This package implements Talon's semantic cache for LLM completions: cost and latency optimization by serving similar prompts from cache instead of calling the LLM. The cache is **GDPR Article 17 compliant**, PII-safe, tenant-isolated, and auditable.

## Cache vs memory (clarification)

| Aspect       | **Semantic cache** (this package)     | **Agent memory** (`internal/memory`)        |
| ------------ | -------------------------------------- | ------------------------------------------- |
| **Layer**    | Gateway / proxy (LLM request path)     | Agent (per-agent learning)                  |
| **Purpose**  | Cost and latency: reuse similar prompts| Safety and compliance: what the agent may remember |
| **Duration** | Minutes to days (TTL, eviction)        | Weeks to indefinitely                       |
| **Governance** | Cache TTL, data tier, PII scrubbing, GDPR erasure | Categories, PII policy, constitutional AI |
| **Config**   | `talon.config.yaml` under `cache`      | `agent.talon.yaml` under `memory`           |
| **When used**| Before every LLM call                  | When building context for later runs        |

The semantic cache sits at the proxy/gateway layer. Memory governance sits at the agent layer. Both may use similar techniques (e.g. embeddings, similarity) for different goals.

## Embedding strategy (Option C — BM25, v0.2.0 default)

We use **BM25-style term-vector similarity** in pure Go (`embedder.go`):

- **No external model or CGO** — single binary, no extra dependencies.
- **Deterministic** — same text always yields the same blob for lookup.
- **Good for exact and near-exact match** — repeated or slightly reworded prompts hit the cache.
- **Does not match paraphrases** (e.g. "What is GDPR?" vs "Explain GDPR to me"); that is an acceptable MVP tradeoff. Most cache hits in practice come from repeated or near-identical queries.

Alternatives deferred to later:

- **Option A (v0.3):** Local embedding model (e.g. ONNX MiniLM) for true semantic matching.
- **Option B (not recommended):** LLM provider embedding API — adds latency and cost to every lookup.

## What is stored

- **Stored:** Prompt embedding (serialized term vector, no raw prompt text), PII-scrubbed response text, metadata (tenant_id, model, TTL, hit_count), HMAC signature.
- **Not stored:** Raw prompt text, raw response text, user identifiers (except optional `user_id` for GDPR user-level erasure).

## Components

- **store.go** — SQLite schema, CRUD, lookup with similarity function, eviction, HMAC, GDPR erasure.
- **embedder.go** — BM25 tokenization and cosine similarity of term vectors.
- **pii_scrubber.go** — Wraps `classifier.Redact` for response text before storage.
- **policy.go** — OPA cache eligibility (data tier, PII, request type, cache_enabled); see `rego/cache.rego`.
