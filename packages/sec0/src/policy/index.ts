import Ajv2020, { type ErrorObject } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { parse as parseYaml } from "yaml";
import { policySchema } from "./schema";
import type { PolicyObject, ValidationResult } from "./types";

export type { PolicyObject, LlmJudgeConfig, PolicyEnforcementReason } from "./types";

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(policySchema);

export function validatePolicy(policy: unknown): ValidationResult & { policy?: PolicyObject } {
  const valid = validate(policy);
  if (valid) {
    return { valid: true, policy: policy as PolicyObject };
  }
  const errors = (validate.errors || []).map(formatAjvError);
  return { valid: false, errors };
}

export function parsePolicyYaml(yamlSource: string): PolicyObject {
  const doc = parseYaml(yamlSource);
  const result = validatePolicy(doc);
  if (!result.valid) {
    const details = (result.errors || []).join("; ");
    throw new Error(`Invalid policy.yaml: ${details}`);
  }
  return result.policy!;
}

export function normalizeAllowlist(raw: unknown): string[] {
  if (!Array.isArray(raw)) return ["*"];
  return raw.map((entry) => String(entry).trim()).filter(Boolean);
}

type AllowlistMatchOptions = {
  serverName?: string;
};

export function matchesAllowlist(
  allowlist: unknown,
  toolName: string,
  opts: AllowlistMatchOptions = {},
): boolean {
  const list = normalizeAllowlist(allowlist);
  if (list.includes("*") || list.includes("mcp://*") || list.includes("mcp://*/*@*")) {
    return true;
  }

  const rawTool = String(toolName || "").trim();
  if (!rawTool) return false;
  const [toolBase, toolVersion] = rawTool.split("@", 2);

  for (const entry of list) {
    if (!entry) continue;
    if (entry === rawTool) return true;
    if (entry === toolBase) return true;
    if (entry.endsWith("@*")) {
      const entryBase = entry.slice(0, -2);
      if (entryBase === toolBase) return true;
    }

    if (!entry.startsWith("mcp://")) continue;
    const rest = entry.slice("mcp://".length);
    if (!rest) continue;
    if (rest === "*") return true;

    const slashIdx = rest.indexOf("/");
    if (slashIdx === -1) {
      const serverOnly = rest;
      if (serverOnly === "*" || (opts.serverName && serverOnly === opts.serverName)) {
        return true;
      }
      continue;
    }

    const serverPart = rest.slice(0, slashIdx);
    const toolPart = rest.slice(slashIdx + 1);
    if (serverPart !== "*" && serverPart !== opts.serverName) continue;
    if (!toolPart || toolPart === "*") return true;

    const [entryTool, entryVersion] = toolPart.split("@", 2);
    if (entryTool !== toolBase) continue;
    if (!entryVersion || entryVersion === "*") return true;
    if (toolVersion && entryVersion === toolVersion) return true;
  }

  return false;
}

function formatAjvError(error: ErrorObject): string {
  const path = error.instancePath || "(root)";
  if (error.keyword === "enum") {
    return `${path} must be one of: ${(error.params as any).allowedValues?.join(", ")}`;
  }
  return `${path} ${error.message}`;
}
