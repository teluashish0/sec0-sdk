// API key based hierarchy resolution for middleware.
// Validates API keys through the control plane and returns tenant/client metadata.

import { resolveControlPlaneUrl } from "./controlPlane";
import { createControlPlaneClient } from "./adapters/controlPlaneClient";

export type HierarchyMetadata = {
  tenant: string;
  env: "prod" | "staging" | "dev";
  clientName: string;
  clientVersion: string;
  userId?: string;
};

const hierarchyCache = new Map<string, { metadata: HierarchyMetadata; controlPlaneUrl?: string; expiresAt: number }>();
const CACHE_TTL_MS = 60_000;

async function tryDiscovery(apiKey: string): Promise<{ controlPlaneUrl: string; metadata: HierarchyMetadata } | null> {
  const defaultUrl = resolveControlPlaneUrl(undefined);
  const client = createControlPlaneClient({ baseUrl: defaultUrl });
  try {
    const data = await client.discover(apiKey);
    const tenant = String(data.tenant || "").trim();
    const env = String(data.env || "").trim();
    const clientName = String(data.clientName || "").trim();
    const clientVersion = String(data.clientVersion || "").trim();
    if (!data.controlPlaneUrl || !tenant || !env || !clientName || !clientVersion) {
      return null;
    }
    return {
      controlPlaneUrl: data.controlPlaneUrl,
      metadata: {
        tenant,
        env: env as HierarchyMetadata["env"],
        clientName,
        clientVersion,
      },
    };
  } catch {
    return null;
  }
}

/**
 * Resolve hierarchy metadata from API key by calling control plane.
 * When controlPlaneUrl is not explicitly provided, this function first tries
 * /api/discover to auto-discover the right control-plane URL.
 */
export async function resolveHierarchyFromApiKey(apiKey: string, controlPlaneUrl?: string): Promise<HierarchyMetadata> {
  if (!apiKey) {
    throw new Error("[apiKeyResolver] API key is required to resolve hierarchy metadata");
  }

  const cached = hierarchyCache.get(apiKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.metadata;
  }

  let effectiveUrl = controlPlaneUrl;
  if (!effectiveUrl) {
    const discovered = await tryDiscovery(apiKey);
    if (discovered) {
      hierarchyCache.set(apiKey, {
        metadata: discovered.metadata,
        controlPlaneUrl: discovered.controlPlaneUrl,
        expiresAt: Date.now() + CACHE_TTL_MS,
      });
      return discovered.metadata;
    }
  }

  const baseUrl = resolveControlPlaneUrl(effectiveUrl);
  const client = createControlPlaneClient({ baseUrl });
  try {
    const data = await client.validateKey(apiKey);
    const metadata: HierarchyMetadata = {
      tenant: data.tenant,
      env: data.env,
      clientName: data.clientName,
      clientVersion: data.clientVersion,
      ...(data.userId ? { userId: data.userId } : {}),
    };
    hierarchyCache.set(apiKey, {
      metadata,
      expiresAt: Date.now() + CACHE_TTL_MS,
    });
    return metadata;
  } catch (error: any) {
    const err = error instanceof Error ? error : new Error(String(error));
    throw new Error(`[apiKeyResolver] Error resolving hierarchy: ${err.message}`);
  }
}

/**
 * Get discovered control-plane URL for a cached API key.
 */
export function getDiscoveredControlPlaneUrl(apiKey: string): string | undefined {
  const cached = hierarchyCache.get(apiKey);
  return cached?.controlPlaneUrl;
}

/**
 * Resolve hierarchy metadata strictly via control plane.
 */
export async function resolveHierarchy(apiKey?: string, opts?: { controlPlaneUrl?: string }): Promise<HierarchyMetadata> {
  if (!apiKey) {
    throw new Error("[apiKeyResolver] API key is required to resolve hierarchy metadata");
  }
  const baseUrl = resolveControlPlaneUrl(opts?.controlPlaneUrl);
  const resolved = await resolveHierarchyFromApiKey(apiKey, baseUrl);
  return resolved;
}

/**
 * Extract API key from common header formats.
 */
export function extractApiKey(headers?: Record<string, string | string[] | undefined>): string {
  if (!headers) {
    throw new Error("[apiKeyResolver] headers are required to extract API key");
  }

  const normalize = (value?: string | string[]): string | undefined => {
    if (Array.isArray(value)) return typeof value[0] === "string" ? value[0].trim() : undefined;
    if (typeof value === "string") {
      const trimmed = value.trim();
      return trimmed.length ? trimmed : undefined;
    }
    return undefined;
  };

  const apiKeyHeader = normalize(headers["x-api-key"] ?? headers["X-API-Key"]);
  if (apiKeyHeader) return apiKeyHeader;

  const authHeader = normalize(headers["authorization"] ?? headers["Authorization"]);
  if (authHeader) {
    const match = authHeader.match(/^Bearer\s+((?:worm|sec0)[_-][A-Za-z0-9._-]{8,1024})$/i);
    if (match) return match[1];
  }

  throw new Error("[apiKeyResolver] Missing API key in headers");
}
