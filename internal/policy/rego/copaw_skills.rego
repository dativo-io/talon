# CoPaw skill governance: allow/deny and policy for skill categories.
# Used when Talon governs CoPaw skill invocations (e.g. via MCP bridge).
# Input: { "skill_name": string, "skill_category": string, "params": object }
# Optional data.policy.copaw.skills for .talon.yaml copaw.skills block.

package talon.policy.copaw_skills

import rego.v1

default allow := true

allow if {
	not deny
}

# Skill category policy: when data.policy.copaw is present, enforce per-category rules.
# Categories: web_search, file_read, file_write, external_api, digest_send
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "file_write"
	data.policy.copaw.skills.file_write == "deny_sensitive_paths"
	sensitive_path(input.params)
	msg := "CoPaw skill file_write denied: path is sensitive"
}

deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "file_write"
	data.policy.copaw.skills.file_write == "deny"
	msg := "CoPaw skill file_write denied by policy"
}

deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "external_api"
	data.policy.copaw.skills.external_api.allowlist != null
	request_host := input.params.host
	not allowed_host(request_host, data.policy.copaw.skills.external_api.allowlist)
	msg := sprintf("CoPaw external_api skill: host %s not in allowlist", [request_host])
}

# digest_send: when require_approval is tier_1 or higher, deny unless approval present (input.approved).
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "digest_send"
	data.policy.copaw.skills.digest_send.require_approval == "tier_1"
	input.approved != true
	msg := "CoPaw digest_send requires approval"
}

# Helper: sensitive path patterns (simplified; extend as needed).
sensitive_path(params) if {
	path := params.path
	path != ""
	contains(path, "/etc/")
}

sensitive_path(params) if {
	path := params.path
	path != ""
	contains(path, ".env")
}

allowed_host(host, allowlist) if {
	host == ""
}

allowed_host(host, allowlist) if {
	some allowed in allowlist
	host == allowed
}

allowed_host(host, allowlist) if {
	some allowed in allowlist
	contains(host, allowed)
}
