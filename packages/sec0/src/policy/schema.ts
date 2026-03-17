// JSON Schema for PolicyObject
export const policySchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://worm.ai/schemas/mcp-policy.schema.json",
  type: "object",
  required: [
    "tenant",
    "default_retention",
    "signing",
    "observability",
    "tools",
    "privacy",
    "side_effects",
    "enforcement",
    "sec0_export"
  ],
  additionalProperties: false,
  properties: {
    tenant: { type: "string", minLength: 1 },
    security_level: { type: "string", enum: ["gateway", "middleware"] },
    default_retention: { type: "string", pattern: "^(30d|90d|180d)$" },
    signing: {
      type: "object",
      required: ["enabled", "key_ref"],
      additionalProperties: false,
      properties: {
        enabled: { type: "boolean" },
        key_ref: { type: "string", minLength: 1 }
      }
    },
    observability: {
      type: "object",
      required: ["otlp_endpoint", "sample"],
      additionalProperties: false,
      properties: {
        otlp_endpoint: { type: "string", minLength: 1 },
        sample: {
          type: "object",
          required: ["success", "error"],
          additionalProperties: false,
          properties: {
            success: { type: "number", minimum: 0, maximum: 1 },
            error: { type: "number", minimum: 0, maximum: 1 }
          }
        },
        enabled: { type: "boolean", default: true },
        sampling: {
          type: "object",
          additionalProperties: false,
          properties: {
            success_ratio: { type: "number", minimum: 0, maximum: 1 },
            error_always: { type: "boolean" }
          }
        },
        redact_identities: { type: "boolean" },
        instrumentation: {
          type: "object",
          additionalProperties: false,
          properties: {
            enabled: { type: "boolean" },
            allow_sdk_attach: { type: "boolean" },
            default_op: { type: "string" }
          }
        }
      }
    },
    tools: {
      type: "object",
      required: ["allowlist", "deny_if_unpinned_version"],
      additionalProperties: false,
      properties: {
        allowlist: {
          type: "array",
          items: { type: "string" },
          default: []
        },
        deny_if_unpinned_version: { type: "boolean" }
      }
    },
    skills: {
      type: "object",
      required: ["allowlist", "deny_if_unpinned_version"],
      additionalProperties: false,
      properties: {
        allowlist: {
          type: "array",
          items: { type: "string" },
          default: []
        },
        deny_if_unpinned_version: { type: "boolean" },
        scan_on_change_only: { type: "boolean" },
        block_on_change: { type: "boolean" },
        block_on_severity: { type: "string", enum: ["low", "medium", "high", "critical"] }
      }
    },
    privacy: {
      type: "object",
      required: [
        "redact_outputs",
        "store_raw_payloads",
        "artifact_retention"
      ],
      additionalProperties: false,
      properties: {
        redact_outputs: { type: "boolean" },
        store_raw_payloads: { type: "boolean" },
        artifact_retention: {
          type: "object",
          required: ["public", "pii", "phi"],
          additionalProperties: false,
          properties: {
            public: { type: "string" },
            pii: { type: "string" },
            phi: { type: "string" }
          }
        }
      }
    },
    side_effects: {
      type: "object",
      required: ["require_idempotency_key", "max_retries"],
      additionalProperties: false,
      properties: {
        require_idempotency_key: { type: "boolean" },
        max_retries: { type: "number", minimum: 0, maximum: 10 }
      }
    },
    enforcement: {
      type: "object",
      required: ["deny_on", "circuit_breakers"],
      additionalProperties: false,
      properties: {
        deny_on: {
          type: "array",
          items: {
            type: "string",
            enum: [
              "missing_audit_signature",
              "tool_not_in_allowlist",
              "version_unpinned",
              "missing_idempotency_for_side_effect",
              "egress_violation",
              "fs_violation",
              "payload_too_large",
              "duration_too_long",
              "registry_mutation",
              "handler_swap",
              "server_code_changed",
              "tool_code_changed",
              "skill_version_changed",
              "skill_code_changed",
              "skill_scan_pending",
              "skill_scan_failed",
              "sast_pending",
              "sast_failed",
              "dast_pending",
              "dast_failed",
              "agent_guard_failed",
              "contextual_evaluator_denied",
              "contextual_evaluator_escalated"
            ]
          }
        },
        escalate_on: {
          type: "array",
          items: {
            type: "string",
            enum: [
              "missing_audit_signature",
              "tool_not_in_allowlist",
              "version_unpinned",
              "missing_idempotency_for_side_effect",
              "egress_violation",
              "fs_violation",
              "payload_too_large",
              "duration_too_long",
              "registry_mutation",
              "handler_swap",
              "server_code_changed",
              "tool_code_changed",
              "skill_version_changed",
              "skill_code_changed",
              "skill_scan_pending",
              "skill_scan_failed",
              "sast_pending",
              "sast_failed",
              "dast_pending",
              "dast_failed",
              "agent_guard_failed",
              "contextual_evaluator_denied",
              "contextual_evaluator_escalated"
            ]
          }
        },
        agent_guard: {
          type: 'object',
          additionalProperties: false,
          properties: {
            enabled: { type: 'boolean' },
            block_on_severity: { type: 'string', enum: ['low','medium','high','critical'] },
            block_on_count: { type: 'number', minimum: 1 }
          }
        },
        circuit_breakers: {
          type: "object",
          required: ["error_rate_pct", "p95_latency_ms"],
          additionalProperties: false,
          properties: {
            error_rate_pct: { type: "number", minimum: 0, maximum: 100 },
            p95_latency_ms: { type: "number", minimum: 0 }
          }
        }
      }
    },
    agent_guard: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        block_on_severity: { type: 'string', enum: ['low','medium','high','critical'] },
        block_on_count: { type: 'number', minimum: 1 }
      }
    },
    compliance: {
      type: 'object',
      additionalProperties: false,
      properties: {
        packs: {
          type: 'array',
          items: {
            type: 'object',
            required: ['id', 'name'],
            additionalProperties: false,
            properties: {
              id: { type: 'string', minLength: 1 },
              name: { type: 'string', minLength: 1 },
              description: { type: 'string' },
              rules: {
                type: 'array',
                items: {
                  type: 'object',
                  required: ['id'],
                  additionalProperties: false,
                  properties: {
                    id: { type: 'string', minLength: 1 },
                    name: { type: 'string' },
                    type: { type: 'string', enum: ['regex', 'nl'] },
                    location: { type: 'string', enum: ['input','output','both','run'] },
                    severity: { type: 'string', enum: ['low','medium','high','critical'] },
                    message: { type: 'string' },
                    patterns: { type: 'array', items: { type: 'string' } },
                    instruction: { type: 'string', minLength: 1 },
                    threshold: { type: 'number', minimum: 0, maximum: 100 },
                    tags: { type: 'array', items: { type: 'string' } },
                  },
                  allOf: [
                    {
                      if: { properties: { type: { const: 'nl' } }, required: ['type'] },
                      then: {
                        required: ['instruction', 'threshold'],
                        // Ajv strict mode requires required props to be defined in the same schema object.
                        properties: {
                          instruction: { type: 'string', minLength: 1 },
                          threshold: { type: 'number', minimum: 0, maximum: 100 },
                        },
                      },
                      else: {
                        // Back-compat: if type is omitted, treat as regex and require patterns
                        required: ['patterns'],
                        properties: {
                          patterns: { type: 'array', items: { type: 'string' }, minItems: 1 },
                        },
                      },
                    },
                  ],
                }
              }
            }
          },
          default: []
        },
        policies: {
          type: 'array',
          items: {
            type: 'object',
            required: ['id', 'name', 'enabled', 'pack_ids'],
            additionalProperties: false,
            properties: {
              id: { type: 'string', minLength: 1 },
              name: { type: 'string', minLength: 1 },
              enabled: { type: 'boolean' },
              pack_ids: { type: 'array', items: { type: 'string' }, default: [] }
            }
          },
          default: []
        }
      }
    },
    security: {
      type: "object",
      additionalProperties: false,
      properties: {
        allow_versions: {
          type: "object",
          additionalProperties: {
            type: "array",
            items: { type: "string" }
          }
        },
        egress_allowlist: { type: "array", items: { type: "string" } },
        fs_allowlist: { type: "array", items: { type: "string" } },
        limits: {
          type: "object",
          additionalProperties: false,
          properties: {
            max_payload_kb: { type: "number", minimum: 0 },
            max_duration_ms: { type: "number", minimum: 0 }
          }
        },
        side_effects: {
          type: "object",
          additionalProperties: false,
          properties: {
            require_idempotency_key: { type: "boolean" },
            approve_high_risk: { type: "boolean" },
            escalation_ttl_seconds: { type: "number", minimum: 1 },
            ttl_seconds: { type: "number", minimum: 1 },
            escalationTtlSeconds: { type: "number", minimum: 1 },
            escalation_on_timeout: { type: "string", enum: ["auto_approve", "auto_reject"] },
            timeout_action: { type: "string", enum: ["auto_approve", "auto_reject"] },
            escalationOnTimeout: { type: "string", enum: ["auto_approve", "auto_reject"] },
            human_escalation: {
              type: "object",
              additionalProperties: false,
              properties: {
                approval_strategy: {
                  type: "string",
                  enum: ["auto_allow", "single_approver", "human_quorum"],
                },
                timeout_action: { type: "string", enum: ["auto_approve", "auto_reject"] },
                min_approvals: { type: "number", minimum: 1 },
                min_rejections: { type: "number", minimum: 1 },
                required_roles: { type: "array", items: { type: "string" } },
                veto_roles: { type: "array", items: { type: "string" } },
                approval_set_id: { type: "string" },
              },
            },
            humanEscalation: {
              type: "object",
              additionalProperties: false,
              properties: {
                approval_strategy: {
                  type: "string",
                  enum: ["auto_allow", "single_approver", "human_quorum"],
                },
                timeout_action: { type: "string", enum: ["auto_approve", "auto_reject"] },
                min_approvals: { type: "number", minimum: 1 },
                min_rejections: { type: "number", minimum: 1 },
                required_roles: { type: "array", items: { type: "string" } },
                veto_roles: { type: "array", items: { type: "string" } },
                approval_set_id: { type: "string" },
              },
            },
          }
        }
      }
    },
    sec0_export: {
      type: "object",
      required: ["enabled", "bucket_uri"],
      additionalProperties: false,
      properties: {
        enabled: { type: "boolean" },
        cadence: { type: "string", enum: ["daily", "weekly", "monthly"] },
        bucket_uri: { type: "string" }
      }
    }
  }
} as const;
