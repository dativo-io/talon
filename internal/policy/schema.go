package policy

import (
	"encoding/json"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

// schemaV2 is the JSON Schema for .talon.yaml v2.0 configuration.
const schemaV2 = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": ".talon.yaml Configuration",
  "description": "Dativo Talon agent policy configuration v2.0",
  "type": "object",
  "required": ["agent", "policies"],
  "additionalProperties": true,
  "properties": {
    "agent": {
      "type": "object",
      "required": ["name", "version"],
      "properties": {
        "name": {"type": "string", "minLength": 1, "pattern": "^[a-z0-9_-]+$"},
        "description": {"type": "string"},
        "version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
        "model_tier": {"type": "integer", "minimum": 0, "maximum": 2}
      }
    },
    "capabilities": {
      "type": "object",
      "properties": {
        "allowed_tools": {"type": "array", "items": {"type": "string"}},
        "allowed_data_sources": {"type": "array", "items": {"type": "string"}},
        "forbidden_patterns": {"type": "array", "items": {"type": "string"}}
      }
    },
    "triggers": {
      "type": "object",
      "properties": {
        "schedule": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["cron", "prompt"],
            "properties": {
              "cron": {"type": "string"},
              "prompt": {"type": "string"},
              "description": {"type": "string"}
            }
          }
        },
        "webhooks": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["name", "source", "prompt_template"],
            "properties": {
              "name": {"type": "string", "pattern": "^[a-z0-9-]+$"},
              "source": {"type": "string", "enum": ["generic", "github", "jira", "slack"]},
              "prompt_template": {"type": "string"},
              "require_approval": {"type": "boolean"}
            }
          }
        }
      }
    },
    "secrets": {
      "type": "object",
      "properties": {
        "allowed": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["name"],
            "properties": {
              "name": {"type": "string"},
              "purpose": {"type": "string"}
            }
          }
        },
        "forbidden": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["name"],
            "properties": {
              "name": {"type": "string"}
            }
          }
        }
      }
    },
    "memory": {
      "type": "object",
      "properties": {
        "enabled": {"type": "boolean"},
        "mode": {"type": "string", "enum": ["active", "shadow", "disabled"]},
        "max_entries": {"type": "integer", "minimum": 1},
        "max_entry_size_kb": {"type": "integer", "minimum": 1},
        "max_prompt_tokens": {"type": "integer", "minimum": 0},
        "retention_days": {"type": "integer", "minimum": 1},
        "review_mode": {"type": "string", "enum": ["auto", "human-review", "read-only"]},
        "allowed_categories": {"type": "array", "items": {"type": "string"}},
        "forbidden_categories": {"type": "array", "items": {"type": "string"}},
        "prompt_categories": {"type": "array", "items": {"type": "string"}},
        "audit": {"type": "boolean"},
        "governance": {
          "type": "object",
          "properties": {
            "conflict_resolution": {"type": "string", "enum": ["auto", "flag_for_review", "reject"]},
            "conflict_similarity_threshold": {"type": "number", "minimum": 0, "maximum": 1},
            "trust_score_overrides": {"type": "boolean"}
          }
        }
      }
    },
    "context": {
      "type": "object",
      "properties": {
        "shared_mounts": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["name", "classification"],
            "properties": {
              "name": {"type": "string"},
              "path": {"type": "string"},
              "description": {"type": "string"},
              "classification": {"type": "string", "enum": ["tier_0", "tier_1", "tier_2"]}
            }
          }
        }
      }
    },
    "attachment_handling": {
      "type": "object",
      "properties": {
        "mode": {"type": "string", "enum": ["strict", "permissive", "disabled"]},
        "require_user_approval": {"type": "array", "items": {"type": "string"}},
        "auto_allow": {"type": "array", "items": {"type": "string"}},
        "scanning": {
          "type": "object",
          "properties": {
            "detect_instructions": {"type": "boolean"},
            "action_on_detection": {"type": "string", "enum": ["block_and_flag", "warn", "log_only"]}
          }
        },
        "sandboxing": {
          "type": "object",
          "properties": {
            "wrap_content": {"type": "boolean"}
          }
        }
      }
    },
    "policies": {
      "type": "object",
      "required": ["cost_limits"],
      "properties": {
        "cost_limits": {
          "type": "object",
          "properties": {
            "per_request": {"type": "number", "minimum": 0},
            "daily": {"type": "number", "minimum": 0},
            "monthly": {"type": "number", "minimum": 0},
            "degradation": {
              "type": "object",
              "properties": {
                "enabled": {"type": "boolean"},
                "threshold_percent": {"type": "number", "minimum": 0, "maximum": 100},
                "fallback_model": {"type": "string"},
                "notify": {"type": "boolean"}
              }
            },
            "budget_alert_webhook": {"type": "string", "format": "uri"}
          }
        },
        "resource_limits": {
          "type": "object",
          "properties": {
            "cpu": {"type": "string"},
            "memory": {"type": "string"},
            "ephemeral_storage": {"type": "string"},
            "max_iterations": {"type": "integer", "minimum": 0, "maximum": 50},
            "max_tool_calls_per_run": {"type": "integer", "minimum": 0},
            "max_cost_per_run": {"type": "number", "minimum": 0},
            "timeout": {
              "type": "object",
              "properties": {
                "operation": {"type": "string"},
                "tool_execution": {"type": "string"},
                "agent_total": {"type": "string"}
              }
            }
          }
        },
        "rate_limits": {
          "type": "object",
          "properties": {
            "requests_per_minute": {"type": "integer", "minimum": 1},
            "concurrent_executions": {"type": "integer", "minimum": 1}
          }
        },
        "data_classification": {
          "type": "object",
          "properties": {
            "input_scan": {"type": "boolean"},
            "output_scan": {"type": "boolean"},
            "redact_pii": {"type": "boolean"},
            "enabled_entities": {"type": "array", "items": {"type": "string"}},
            "disabled_entities": {"type": "array", "items": {"type": "string"}},
            "custom_recognizers": {
              "type": "array",
              "items": {
                "type": "object",
                "required": ["name", "supported_entity"],
                "properties": {
                  "name": {"type": "string"},
                  "supported_entity": {"type": "string"},
                  "sensitivity": {"type": "integer", "minimum": 1, "maximum": 3},
                  "patterns": {
                    "type": "array",
                    "items": {
                      "type": "object",
                      "required": ["name", "regex"],
                      "properties": {
                        "name": {"type": "string"},
                        "regex": {"type": "string"},
                        "score": {"type": "number", "minimum": 0, "maximum": 1}
                      }
                    }
                  }
                }
              }
            }
          }
        },
        "model_routing": {
          "type": "object",
          "properties": {
            "tier_0": {
              "type": "object",
              "properties": {
                "primary": {"type": "string"},
                "fallback": {"type": "string"},
                "location": {"type": "string"}
              }
            },
            "tier_1": {
              "type": "object",
              "properties": {
                "primary": {"type": "string"},
                "fallback": {"type": "string"},
                "location": {"type": "string"},
                "bedrock_only": {"type": "boolean"}
              }
            },
            "tier_2": {
              "type": "object",
              "properties": {
                "primary": {"type": "string"},
                "location": {"type": "string"},
                "bedrock_only": {"type": "boolean"}
              }
            }
          }
        },
        "time_restrictions": {
          "type": "object",
          "properties": {
            "enabled": {"type": "boolean"},
            "allowed_hours": {"type": "string"},
            "timezone": {"type": "string"},
            "weekends": {"type": "boolean"}
          }
        }
      }
    },
    "audit": {
      "type": "object",
      "properties": {
        "log_level": {"type": "string", "enum": ["minimal", "detailed", "full"]},
        "retention_days": {"type": "integer", "minimum": 1},
        "include_prompts": {"type": "boolean"},
        "include_responses": {"type": "boolean"},
        "observation_only": {"type": "boolean"}
      }
    },
    "compliance": {
      "type": "object",
      "additionalProperties": true,
      "properties": {
        "frameworks": {"type": "array", "items": {"type": "string"}},
        "data_residency": {"type": "string"},
        "ai_act_risk_level": {"type": "string", "enum": ["minimal", "limited", "high"]},
        "human_oversight": {"type": "string", "enum": ["none", "on-demand", "always"]}
      }
    },
    "metadata": {
      "type": "object",
      "properties": {
        "department": {"type": "string"},
        "owner": {"type": "string"},
        "created_at": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}}
      }
    }
  }
}`

// ValidateSchema validates YAML policy bytes against the v2.0 JSON schema.
// The YAML is first converted to JSON because gojsonschema operates on JSON.
// If strict is true, additional business-rule checks are applied.
func ValidateSchema(yamlBytes []byte, strict bool) error {
	// Convert YAML to a generic map, then marshal to JSON
	var raw interface{}
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return fmt.Errorf("parsing YAML for schema validation: %w", err)
	}

	// yaml.v3 unmarshals map keys as string, but we need to ensure
	// nested maps also use string keys for JSON marshalling.
	normalized := normalizeYAML(raw)

	jsonBytes, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("converting YAML to JSON: %w", err)
	}

	schemaLoader := gojsonschema.NewStringLoader(schemaV2)
	documentLoader := gojsonschema.NewBytesLoader(jsonBytes)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	if !result.Valid() {
		var errMsg string
		for _, verr := range result.Errors() {
			errMsg += fmt.Sprintf("- %s\n", verr)
		}
		return fmt.Errorf("schema validation errors:\n%s", errMsg)
	}

	if strict {
		if err := strictValidation(jsonBytes); err != nil {
			return err
		}
	}

	return nil
}

// strictValidation applies additional business-rule checks beyond schema.
// Strict mode enforces compliance posture: cost budgets, compliance declaration, and audit config.
func strictValidation(jsonBytes []byte) error {
	var doc map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return fmt.Errorf("parsing policy for strict validation: %w", err)
	}

	// 1. Cost limits must have at least daily OR monthly set
	policies, ok := doc["policies"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("strict mode: policies section is invalid")
	}

	costLimits, ok := policies["cost_limits"].(map[string]interface{})
	if !ok || len(costLimits) == 0 {
		return fmt.Errorf("strict mode: at least one cost limit must be set")
	}

	// Must have daily or monthly (per-request alone is insufficient governance)
	_, hasDaily := costLimits["daily"]
	_, hasMonthly := costLimits["monthly"]
	if !hasDaily && !hasMonthly {
		return fmt.Errorf("strict mode: cost_limits must include 'daily' or 'monthly' budget")
	}

	// 2. Compliance section required in strict mode
	if _, ok := doc["compliance"]; !ok {
		return fmt.Errorf("strict mode: 'compliance' section is required (set frameworks, data_residency)")
	}

	// 3. Audit section must exist
	if _, ok := doc["audit"]; !ok {
		return fmt.Errorf("strict mode: 'audit' section is required for compliance")
	}

	return nil
}

// normalizeYAML recursively converts map[interface{}]interface{} to
// map[string]interface{} so that json.Marshal can handle it.
func normalizeYAML(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, v := range val {
			out[k] = normalizeYAML(v)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, v := range val {
			out[fmt.Sprintf("%v", k)] = normalizeYAML(v)
		}
		return out
	case []interface{}:
		for i, item := range val {
			val[i] = normalizeYAML(item)
		}
		return val
	default:
		return v
	}
}
