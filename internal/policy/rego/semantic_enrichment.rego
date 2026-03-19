package talon.policy.semantic_enrichment

import rego.v1

# Semantic enrichment policy: decides which attributes may be emitted for
# placeholders. Mode off = no attributes; shadow = computed but not rendered (handled in Go);
# enforce = emit attributes allowed by rules below.

# Default: emit no attributes (fail safe)
default emit_attributes := []

# When mode is "off", emit nothing.
emit_attributes := [] if {
	input.config.mode == "off"
}

# When mode is "shadow", emit nothing (enricher runs, telemetry only; renderer uses legacy format).
emit_attributes := [] if {
	input.config.mode == "shadow"
}

# When mode is "enforce", emit only allowed attributes that are present on the entity.
emit_attributes := allowed if {
	input.config.mode == "enforce"
	input.entity.attributes != null
	input.config.allowed_attributes != null
	allowed := [a | a := input.config.allowed_attributes[_]; input.entity.attributes[a] != null]
}

# Normalize/fallback: allowed_attributes defaults to person and location attributes if not set.
# (Handled in Go by passing allowed_attributes from config; this file only reads input.config.allowed_attributes.)
