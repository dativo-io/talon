package talon.policy.routing

import rego.v1

test_eu_strict_blocks_cn_jurisdiction if {
	count(deny) > 0 with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "CN", "provider_id": "qwen"}
	"provider jurisdiction CN not allowed in eu_strict" in deny with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "CN", "provider_id": "qwen"}
}

test_eu_strict_blocks_us_jurisdiction if {
	count(deny) > 0 with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "US", "provider_id": "openai"}
	"provider jurisdiction US not allowed in eu_strict" in deny with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "US", "provider_id": "openai"}
}

test_eu_strict_allows_eu_jurisdiction if {
	allow with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "EU", "provider_id": "mistral"}
	count(deny) == 0 with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "EU", "provider_id": "mistral"}
}

test_eu_strict_allows_local_jurisdiction if {
	allow with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "LOCAL", "provider_id": "ollama"}
	count(deny) == 0 with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "LOCAL", "provider_id": "ollama"}
}

test_eu_strict_blocks_azure_us_region if {
	count(deny) > 0 with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "US", "provider_id": "azure-openai", "provider_region": "eastus"}
	"Azure with non-EU region not allowed in eu_strict" in deny with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "US", "provider_id": "azure-openai", "provider_region": "eastus"}
}

# Azure metadata has Jurisdiction "EU"; when user selects US region (eastus), eu_strict must still deny.
test_eu_strict_blocks_azure_eu_jurisdiction_us_region if {
	count(deny) > 0 with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "EU", "provider_id": "azure-openai", "provider_region": "eastus"}
	"provider region is not in allowed EU regions for eu_strict" in deny with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "EU", "provider_id": "azure-openai", "provider_region": "eastus"}
}

test_eu_strict_allows_azure_eu_region if {
	allow with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "EU", "provider_id": "azure-openai", "provider_region": "westeurope"}
	count(deny) == 0 with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "EU", "provider_id": "azure-openai", "provider_region": "westeurope"}
}

test_eu_preferred_allows_us_when_eu_down if {
	# In eu_preferred we allow US (fallback is applied by router, not policy).
	allow with input as {"sovereignty_mode": "eu_preferred", "provider_jurisdiction": "US", "provider_id": "openai"}
}

test_confidential_tier_local_only if {
	count(deny) > 0 with input as {"sovereignty_mode": "eu_strict", "data_tier": 2, "require_eu_routing": true, "provider_jurisdiction": "EU", "provider_id": "mistral"}
	"confidential tier requires LOCAL provider only" in deny with input as {"sovereignty_mode": "eu_strict", "data_tier": 2, "require_eu_routing": true, "provider_jurisdiction": "EU", "provider_id": "mistral"}
}

test_confidential_tier_blocks_cloud_eu if {
	count(deny) > 0 with input as {"data_tier": 2, "require_eu_routing": true, "provider_jurisdiction": "EU", "provider_id": "azure-openai"}
	"confidential tier blocks cloud providers" in deny with input as {"data_tier": 2, "require_eu_routing": true, "provider_jurisdiction": "EU", "provider_id": "azure-openai"}
}

test_global_mode_allows_all if {
	allow with input as {"sovereignty_mode": "global", "provider_jurisdiction": "CN", "provider_id": "qwen"}
	allow with input as {"sovereignty_mode": "global", "provider_jurisdiction": "US", "provider_id": "openai"}
	count(deny) == 0 with input as {"sovereignty_mode": "global", "provider_jurisdiction": "US", "provider_id": "openai"}
}

test_deny_reason_populated if {
	# When denied, deny set is non-empty (for evidence).
	reasons := deny with input as {"sovereignty_mode": "eu_strict", "provider_jurisdiction": "CN", "provider_id": "qwen"}
	count(reasons) > 0
	some r in reasons
	r != ""
}
