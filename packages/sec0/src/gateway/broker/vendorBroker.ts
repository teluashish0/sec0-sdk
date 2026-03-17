import { readFileSync } from "node:fs";
import path from "node:path";

// Broker helpers resolve vendor credentials from a variety of sources and
// inject them as headers before the gateway forwards a request upstream.

// Declarative broker configuration describing how to fetch and inject a key.
export type BrokerConfig = {
  type: "vendor_key_pool" | "oidc_on_behalf" | "static";
  inject: { header: string; format: "raw" | "bearer" | "template" };
  key_refs?: string[];
}

// Resolved broker output that the middleware feeds into upstream requests.
export type BrokerResult = { headers: Record<string,string>; name: string; key_id?: string };

const DEFAULT_BROKER_SECRET_DIRS = [
  path.resolve(process.cwd(), ".sec0/secrets"),
  path.resolve(process.cwd(), "secrets"),
  path.resolve(process.cwd(), "config/secrets"),
];

function parseAllowedDirs(raw: string | undefined, fallback: string[]): string[] {
  if (!raw || raw.trim().length === 0) return fallback;
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => path.resolve(entry));
}

function isWithinAllowedDir(candidate: string, allowedDir: string): boolean {
  const rel = path.relative(allowedDir, candidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function resolveAllowedSecretPath(ref: string): string {
  const rawPath = ref.slice("file://".length).trim();
  if (!rawPath) {
    throw new Error("file:// secret reference path is empty");
  }
  const resolved = path.resolve(rawPath);
  const allowedDirs = parseAllowedDirs(process.env.SEC0_BROKER_SECRET_DIRS, DEFAULT_BROKER_SECRET_DIRS);
  if (!allowedDirs.some((allowedDir) => isWithinAllowedDir(resolved, allowedDir))) {
    throw new Error(
      `file:// secret path "${resolved}" is outside allowed directories. Set SEC0_BROKER_SECRET_DIRS to permit it.`,
    );
  }
  return resolved;
}

/**
 * Resolve vendor headers based on the configured broker type and reference.
 * Throws loudly when required secrets are missing to avoid silent pass-through.
 */
export async function getVendorHeaders(cfg: BrokerConfig): Promise<BrokerResult> {
  if (cfg.type === "static") {
    const keyRef = cfg.key_refs?.[0];
    if (!keyRef) {
      throw new Error("BrokerConfig with type 'static' requires at least one key_ref");
    }
    const token = resolveSecret(keyRef);
    if (!token) {
      throw new Error(`Failed to resolve static broker secret for ref '${keyRef}'`);
    }
    return {
      headers: { [cfg.inject.header]: formatToken(token, cfg.inject.format) },
      name: "static",
    };
  }
  if (cfg.type === "vendor_key_pool") {
    const keyId = cfg.key_refs?.[0];
    if (!keyId) {
      throw new Error("BrokerConfig with type 'vendor_key_pool' requires at least one key_ref");
    }
    const token = resolveSecret(keyId);
    if (!token) {
      throw new Error(`Failed to resolve vendor key pool secret for ref '${keyId}'`);
    }
    return {
      headers: { [cfg.inject.header]: formatToken(token, cfg.inject.format) },
      name: "vendor_key_pool",
      key_id: keyId,
    };
  }
  if (cfg.type === "oidc_on_behalf") {
    const token = process.env.VENDOR_OBO_TOKEN;
    if (!token) {
      throw new Error("Environment variable 'VENDOR_OBO_TOKEN' is required for broker type 'oidc_on_behalf'");
    }
    return {
      headers: { [cfg.inject.header]: formatToken(token, cfg.inject.format) },
      name: "oidc_on_behalf",
    };
  }
  throw new Error(`Unsupported broker type '${(cfg as any).type}'`);
}

/**
 * Produce the wire representation for a vendor token. Template support can be
 * extended later (currently pass-through for compat).
 */
function formatToken(token: string, fmt: "raw" | "bearer" | "template"): string {
  if (fmt === "bearer") return `Bearer ${token}`;
  if (fmt === "template") return token; // extend to support templates like `Bearer ${token}`
  return token;
}

/**
 * Resolve a secret reference to its actual token. Supports env, file://, and
 * plain inline values; falls back to namespaced env keys for local dev.
 */
function resolveSecret(ref?: string): string | undefined {
  if (!ref) return undefined;
  if (ref.startsWith('env:')) return process.env[ref.slice(4)];
  if (ref.startsWith('file://')) {
    try {
      const allowedPath = resolveAllowedSecretPath(ref);
      return readFileSync(allowedPath).toString().trim();
    } catch {
      return undefined;
    }
  }
  if (ref.startsWith('plain:')) {
    if (process.env.SEC0_ALLOW_INLINE_BROKER_SECRETS === "true") {
      return ref.slice(6);
    }
    throw new Error(
      "Inline plain: broker secrets are disabled by default. Use env: or file:// refs instead.",
    );
  }
  // kms:// not implemented in dev
  return process.env['BROKER_SECRET_'+ref.replace(/[^A-Za-z0-9_]/g,'_')];
}

