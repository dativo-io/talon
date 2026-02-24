package talon.policy.memory_governance

import rego.v1

# Memory write governance - Constitutional AI pattern
default allow := false

allow if {
	not deny
}

deny contains msg if {
	not category_allowed(input.category)
	msg := sprintf("Memory category '%s' not in allowed_categories", [input.category])
}

deny contains msg if {
	category_forbidden(input.category)
	msg := sprintf("Memory category '%s' is forbidden", [input.category])
}

deny contains msg if {
	input.content_size_bytes > data.policy.memory.max_entry_size_kb * 1024
	msg := "Memory entry exceeds max_entry_size_kb"
}

# Sub-types that the legacy inferCategory would have classified as domain_knowledge.
# Policies with allowed_categories including "domain_knowledge" allow these for backward compatibility.
domain_knowledge_subtype(cat) if {
	cat in {"domain_knowledge", "factual_corrections", "user_preferences", "procedure_improvements", "tool_approval", "cost_decision"}
}

category_allowed(cat) if {
	some allowed in data.policy.memory.allowed_categories
	allowed == cat
}

# Legacy policies with only [domain_knowledge, policy_hit] must still allow finer categories.
category_allowed(cat) if {
	"domain_knowledge" in data.policy.memory.allowed_categories
	domain_knowledge_subtype(cat)
}

category_forbidden(cat) if {
	some forbidden in data.policy.memory.forbidden_categories
	forbidden == cat
}

# Always forbidden categories (hardcoded for security)
category_forbidden("policy_modifications")

category_forbidden("prompt_injection")

category_forbidden("credential_data")
