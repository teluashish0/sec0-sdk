import {
  DEFAULT_CONTROL_PLANE_URL,
  DEFAULT_DISCOVERY_CACHE_TTL_SECONDS,
  HIERARCHY_CACHE_TTL_MS,
  LOG_PREFIX,
} from "./constants";
import { withTimeout } from "./http";
import type {
  DiscoveryResult,
  HierarchyResult,
  NormalizedPresignConfig,
  ResolvedPresignConfig,
} from "./types";

/**
 * Resolves tenant/environment/client hierarchy from an API key
 * via the control plane discovery and validate-key endpoints.
 */
export class DiscoveryService {
  private discoveryCache: DiscoveryResult | null = null;
  private hierarchyCache: (HierarchyResult & { expiresAtMs: number }) | null = null;

  // Resolve a fully-populated presign config, filling missing hierarchy
  // fields from cached discovery or remote endpoints.
  async resolveHierarchy(cfg: NormalizedPresignConfig): Promise<ResolvedPresignConfig> {
    if (cfg.tenant && cfg.environment && cfg.clientName && cfg.clientVersion) {
      return cfg as ResolvedPresignConfig;
    }

    const now = Date.now();

    // Check discovery cache
    if (this.discoveryCache && this.discoveryCache.expiresAtMs > now) {
      const dc = this.discoveryCache;
      if (dc.tenant && dc.environment && dc.clientName && dc.clientVersion) {
        return {
          ...cfg,
          apiBaseUrl: dc.controlPlaneUrl || cfg.apiBaseUrl,
          tenant: dc.tenant,
          environment: dc.environment,
          clientName: dc.clientName,
          clientVersion: dc.clientVersion,
        };
      }
    }

    // Check hierarchy cache
    if (this.hierarchyCache && this.hierarchyCache.expiresAtMs > now) {
      const hc = this.hierarchyCache;
      return {
        ...cfg,
        tenant: hc.tenant,
        environment: hc.env,
        clientName: hc.clientName,
        clientVersion: hc.clientVersion,
      };
    }

    // Try discovery endpoint first for default URLs
    if (cfg.apiBaseUrl === DEFAULT_CONTROL_PLANE_URL) {
      try {
        const discovered = await this.discover(cfg.auditKey, cfg.timeoutMs);
        if (discovered.tenant && discovered.environment && discovered.clientName && discovered.clientVersion) {
          return {
            ...cfg,
            apiBaseUrl: discovered.controlPlaneUrl,
            tenant: discovered.tenant,
            environment: discovered.environment,
            clientName: discovered.clientName,
            clientVersion: discovered.clientVersion,
          };
        }
      } catch {
        // Discovery failed; fall back to validate-key
      }
    }

    // Fall back to validate-key endpoint
    const resolved = await this.validateKey(cfg.apiBaseUrl, cfg.auditKey, cfg.timeoutMs);
    this.hierarchyCache = {
      ...resolved,
      expiresAtMs: now + HIERARCHY_CACHE_TTL_MS,
    };
    return {
      ...cfg,
      tenant: resolved.tenant,
      environment: resolved.env,
      clientName: resolved.clientName,
      clientVersion: resolved.clientVersion,
    };
  }

  private async discover(auditKey: string, timeoutMs: number): Promise<DiscoveryResult> {
    const now = Date.now();
    if (this.discoveryCache && this.discoveryCache.expiresAtMs > now) {
      return this.discoveryCache;
    }

    const apiKey = extractApiKey(auditKey);
    const discoveryUrl = `${DEFAULT_CONTROL_PLANE_URL}/api/discover`;

    const res = await withTimeout(timeoutMs, (signal) =>
      fetch(discoveryUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": apiKey },
        body: JSON.stringify({ apiKey }),
        signal,
      })
    );

    if (!res.ok) {
      const errorBody = await res.text().catch(() => "");
      throw new Error(`${LOG_PREFIX} discovery failed with status ${res.status}: ${errorBody}`);
    }

    const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    const controlPlaneUrl = parseStringField(data, "controlPlaneUrl");
    if (!controlPlaneUrl) {
      throw new Error(`${LOG_PREFIX} discovery response missing controlPlaneUrl`);
    }

    const cacheTtlSeconds =
      typeof data?.cacheTtlSeconds === "number"
        ? data.cacheTtlSeconds
        : DEFAULT_DISCOVERY_CACHE_TTL_SECONDS;

    this.discoveryCache = {
      controlPlaneUrl,
      tenant: parseStringField(data, "tenant") ?? "",
      environment: parseStringField(data, "env") ?? "",
      clientName: parseStringField(data, "clientName") ?? "",
      clientVersion: parseStringField(data, "clientVersion") ?? "",
      expiresAtMs: now + cacheTtlSeconds * 1000,
    };

    return this.discoveryCache;
  }

  private async validateKey(
    apiBaseUrl: string,
    auditKey: string,
    timeoutMs: number
  ): Promise<HierarchyResult> {
    const apiKey = extractApiKey(auditKey);
    const url = `${apiBaseUrl.replace(/\/$/, "")}/api/auth/validate-key`;

    const res = await withTimeout(timeoutMs, (signal) =>
      fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": apiKey },
        body: JSON.stringify({ apiKey }),
        signal,
      })
    );

    if (!res.ok) {
      throw new Error(`${LOG_PREFIX} validate-key failed with status ${res.status}`);
    }

    const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    const tenant = parseStringField(data, "tenant");
    const env = parseStringField(data, "env");
    const clientName = parseStringField(data, "clientName");
    const clientVersion = parseStringField(data, "clientVersion");

    if (!tenant || !env || !clientName || !clientVersion) {
      throw new Error(`${LOG_PREFIX} validate-key response missing hierarchy metadata`);
    }

    return { tenant, env, clientName, clientVersion };
  }
}

/**
 * Extract the raw API key from an audit key value (strips "Bearer " prefix if present).
 */
export function extractApiKey(auditKey: string): string {
  const raw = String(auditKey || "").trim();
  if (!raw) {
    throw new Error(`${LOG_PREFIX} auditKey is missing`);
  }
  const match = raw.match(/^Bearer\s+(.+)$/i);
  const token = match?.[1]?.trim() ?? raw;
  if (!token) {
    throw new Error(`${LOG_PREFIX} auditKey does not contain a valid API key`);
  }
  return token;
}

function parseStringField(
  data: Record<string, unknown> | null | undefined,
  field: string
): string | undefined {
  const val = data?.[field];
  if (typeof val !== "string") return undefined;
  const trimmed = val.trim();
  return trimmed || undefined;
}
