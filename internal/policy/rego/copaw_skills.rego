# CoPaw skill governance: allow/deny and policy for skill categories.
# Used when Talon governs CoPaw skill invocations (e.g. via MCP bridge).
# Input: { "skill_name": string, "skill_category": string, "params": object }
# Optional data.policy.copaw.skills for .talon.yaml copaw.skills block.
#
# Semantics: default allow := false so that when any deny rule fires, allow is false.
# (With default true, allow would remain true despite non-empty deny.)

package talon.policy.copaw_skills

import rego.v1

default allow := false

allow if {
	not deny
	known_category(input.skill_category)
}

# Only known skill categories can be allowed; unknown/future categories are denied (fail-closed).
known_category(cat) if {
	cat in {"web_search", "file_read", "file_write", "external_api", "digest_send"}
}

# Skill category policy: when data.policy.copaw is present, enforce per-category rules.
# Categories: web_search, file_read, file_write, external_api, digest_send

# web_search: deny when policy explicitly denies.
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "web_search"
	data.policy.copaw.skills.web_search == "deny"
	msg := "CoPaw skill web_search denied by policy"
}

# file_read: deny when policy explicitly denies.
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "file_read"
	data.policy.copaw.skills.file_read == "deny"
	msg := "CoPaw skill file_read denied by policy"
}

# file_read: deny when policy allows but path is sensitive (e.g. secrets, .env).
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "file_read"
	data.policy.copaw.skills.file_read != "deny"
	sensitive_path(input.params)
	msg := "CoPaw skill file_read denied: path is sensitive"
}

# file_write: deny when path is sensitive and policy uses deny_sensitive_paths.
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "file_write"
	data.policy.copaw.skills.file_write == "deny_sensitive_paths"
	sensitive_path(input.params)
	msg := "CoPaw skill file_write denied: path is sensitive"
}

# file_write: deny when policy explicitly denies.
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "file_write"
	data.policy.copaw.skills.file_write == "deny"
	msg := "CoPaw skill file_write denied by policy"
}

# external_api: when allowlist is set, host is required and must be in allowlist.
# Empty or missing host is denied so skills cannot bypass the allowlist.
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "external_api"
	data.policy.copaw.skills.external_api.allowlist != null
	not external_api_host_non_empty(input.params.host)
	msg := "CoPaw external_api skill: host is required when allowlist is set"
}

deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "external_api"
	data.policy.copaw.skills.external_api.allowlist != null
	request_host := input.params.host
	request_host != ""
	not allowed_host(request_host, data.policy.copaw.skills.external_api.allowlist)
	msg := sprintf("CoPaw external_api skill: host %s not in allowlist", [request_host])
}

# digest_send: when require_approval is tier_1 or tier_2, deny unless approval present (input.approved).
deny contains msg if {
	data.policy.copaw.skills != null
	input.skill_category == "digest_send"
	data.policy.copaw.skills.digest_send.require_approval in {"tier_1", "tier_2"}
	input.approved != true
	msg := "CoPaw digest_send requires approval"
}

# external_api_host_non_empty: true only when host is a non-empty string.
# Used to deny missing/empty host when allowlist is set (no bypass).
external_api_host_non_empty(host) if {
	host != null
	host != ""
}

# Helper: sensitive path patterns for file_read/file_write governance.
# Covers common secrets, config, and system paths that should not be read/written by skills.
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

sensitive_path(params) if {
	path := params.path
	path != ""
	contains(path, ".ssh")
}

sensitive_path(params) if {
	path := params.path
	path != ""
	contains(path, "/var/log/")
}

sensitive_path(params) if {
	path := params.path
	path != ""
	contains(path, ".talon")
}

sensitive_path(params) if {
	path := params.path
	path != ""
	contains(path, "secrets")
}

sensitive_path(params) if {
	path := params.path
	path != ""
	contains(path, "credentials")
}

# allowed_host is true only when host explicitly matches the allowlist.
# Empty host is not allowed when allowlist is set (enforced by deny rule above).
allowed_host(host, allowlist) if {
	some allowed in allowlist
	host == allowed
}

allowed_host(host, allowlist) if {
	some allowed in allowlist
	contains(host, allowed)
}
