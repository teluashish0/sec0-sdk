import YAML from "yaml";
import type { PolicyObject } from "../policy";
import { sha256Hex } from "../signer";
import { extractApiKey } from "./apiKeyResolver";
import { resolveControlPlaneUrl } from "./controlPlane";
import { createControlPlaneClient, type ControlPlaneClient } from "./adapters/controlPlaneClient";

export type ControlPlanePolicySource = {
  source: "control-plane";
  level?: "gateway" | "middleware";
  scope?: "base" | "agent" | "auto";
  nodeId?: string;
  fallbackToBase?: boolean;
  refreshTtlMs?: number;
};

export function isControlPlanePolicySource(value: any): value is ControlPlanePolicySource {
  return !!value && typeof value === "object" && (value as any).source === "control-plane";
}

export type ResolvedControlPlanePolicy = {
  tenant: string;
  env: string;
  clientName: string;
  clientVersion: string;
  level: "gateway" | "middleware";
  nodeId: string | null;
  yaml: string;
  etag: string | null;
  hash: string;
  policy: PolicyObject;
};

type CacheEntry = Omit<ResolvedControlPlanePolicy, "level" | "nodeId"> & { fetchedAtMs: number };

function normalizeNodeId(value?: string | null): string | null {
  const s = String(value || "").trim();
  return s ? s : null;
}

function cacheKey(level: "gateway" | "middleware", nodeId: string | null): string {
  return `${level}::${nodeId || "__base__"}`;
}

function safeParsePolicyYaml(yaml: string): PolicyObject {
  try {
    const parsed = YAML.parse(String(yaml || "")) as any;
    if (!parsed || typeof parsed !== "object") {
      throw new Error("policy_yaml_invalid");
    }
    return parsed as PolicyObject;
  } catch (e: any) {
    throw new Error(`[sec0-middleware] policy_yaml_parse_failed:${e?.message || String(e)}`);
  }
}

function noEnforcementPolicy(): PolicyObject {
  return {
    security_level: "middleware",
    default_retention: "30d",
    tools: { allowlist: ["*"], deny_if_unpinned_version: false } as any,
    enforcement: { deny_on: [], circuit_breakers: {} } as any,
  } as any;
}

export function createControlPlanePolicyManager(opts: {
  controlPlaneUrl?: string;
  auth?: { apiKey?: string; bearerToken?: string };
  source: ControlPlanePolicySource;
  debug?: boolean;
  client?: ControlPlaneClient;
}) {
  const baseUrl = resolveControlPlaneUrl(opts.controlPlaneUrl);
  const client = opts.client ?? createControlPlaneClient({ baseUrl });
  const ttlMs = Number.isFinite(opts.source.refreshTtlMs) ? Math.max(0, Math.floor(opts.source.refreshTtlMs!)) : 0;
  const fallbackToBase = opts.source.fallbackToBase !== false;
  const level: "gateway" | "middleware" =
    opts.source.level === "gateway" || opts.source.level === "middleware"
      ? opts.source.level
      : "middleware";

  const debug = (msg: string, extra?: any) => {
    if (!opts.debug) return;
    try {
      console.log("[sec0-middleware][policy]", msg, extra ?? "");
    } catch {}
  };

  const cache = new Map<string, CacheEntry>();
  const inFlight = new Map<string, Promise<CacheEntry>>();

  const fetchOnce = async (nodeId: string | null): Promise<ResolvedControlPlanePolicy> => {
    const apiKey = extractApiKey({
      "x-api-key": opts.auth?.apiKey,
      authorization: opts.auth?.bearerToken ? `Bearer ${opts.auth?.bearerToken}` : undefined,
    } as any);
    if (!apiKey) {
      throw new Error("[sec0-middleware] auth.apiKey (or bearerToken containing a worm_* key) is required to fetch policy");
    }

    const hierarchy = await client.validateKey(apiKey);
    const tenant = String(hierarchy?.tenant || "").trim();
    const env = String((hierarchy as any)?.env || "").trim();
    const clientName = String((hierarchy as any)?.clientName || "").trim();
    const clientVersion = String((hierarchy as any)?.clientVersion || "").trim();
    if (!tenant) {
      throw new Error("[sec0-middleware] failed_to_resolve_tenant_from_api_key");
    }

    debug("fetch", { level, nodeId, tenant });
    const replayJobId = String(process.env.SEC0_REPLAY_JOB_ID || "").trim();
    const replayRunnerId = String(process.env.SEC0_REPLAY_RUNNER_ID || "").trim();
    const fetched = await client.fetchPolicy({
      tenant,
      level,
      nodeId,
      authToken: apiKey,
      replayJobId,
      replayRunnerId,
    });
    const yaml = fetched.yaml;
    const trimmed = String(yaml || "").trim();
    const etag = fetched.etag;
    const hash = sha256Hex(Buffer.from(trimmed || ""));

    if (!trimmed) {
      return {
        tenant,
        env,
        clientName,
        clientVersion,
        level,
        nodeId,
        yaml: "",
        etag,
        hash,
        policy: noEnforcementPolicy(),
      };
    }

    const policy = safeParsePolicyYaml(yaml);
    return { tenant, env, clientName, clientVersion, level, nodeId, yaml, etag, hash, policy };
  };

  const getCachedOrFetch = async (nodeId: string | null): Promise<ResolvedControlPlanePolicy> => {
    const key = cacheKey(level, nodeId);
    const cached = cache.get(key);
    const now = Date.now();
    if (cached && (ttlMs === 0 ? false : now - cached.fetchedAtMs < ttlMs)) {
      return {
        tenant: cached.tenant,
        env: cached.env,
        clientName: cached.clientName,
        clientVersion: cached.clientVersion,
        level,
        nodeId,
        yaml: cached.yaml,
        etag: cached.etag,
        hash: cached.hash,
        policy: cached.policy,
      };
    }

    const existing = inFlight.get(key);
    if (existing) {
      const v = await existing;
      return {
        tenant: v.tenant,
        env: v.env,
        clientName: v.clientName,
        clientVersion: v.clientVersion,
        level,
        nodeId,
        yaml: v.yaml,
        etag: v.etag,
        hash: v.hash,
        policy: v.policy,
      };
    }

    const p = (async () => {
      const res = await fetchOnce(nodeId);
      const entry: CacheEntry = {
        tenant: res.tenant,
        env: res.env,
        clientName: res.clientName,
        clientVersion: res.clientVersion,
        yaml: res.yaml,
        etag: res.etag,
        hash: res.hash,
        policy: res.policy,
        fetchedAtMs: Date.now(),
      };
      cache.set(key, entry);
      return entry;
    })().finally(() => {
      inFlight.delete(key);
    });
    inFlight.set(key, p);

    const v = await p;
    return {
      tenant: v.tenant,
      env: v.env,
      clientName: v.clientName,
      clientVersion: v.clientVersion,
      level,
      nodeId,
      yaml: v.yaml,
      etag: v.etag,
      hash: v.hash,
      policy: v.policy,
    };
  };

  const resolveEffectiveNodeId = (runtimeNodeId?: string | null): string | null => {
    const scope = opts.source.scope || "auto";
    const runtime = normalizeNodeId(runtimeNodeId);
    const configured = normalizeNodeId(opts.source.nodeId);
    if (scope === "base") return null;
    if (scope === "agent") return runtime || configured;
    return runtime || configured || null;
  };

  return {
    async getPolicy(runtime?: { nodeId?: string | null }): Promise<ResolvedControlPlanePolicy> {
      const nodeId = resolveEffectiveNodeId(runtime?.nodeId);
      const scope = opts.source.scope || "auto";
      if (scope === "agent" && !nodeId) {
        throw new Error("[sec0-middleware] control-plane policy source requires nodeId for scope=agent");
      }

      const res = await getCachedOrFetch(nodeId);
      const hasYaml = !!String(res.yaml || "").trim();
      if (hasYaml) return res;

      if (nodeId && fallbackToBase) {
        debug("empty agent policy; falling back to base", { nodeId });
        const base = await getCachedOrFetch(null);
        return base;
      }

      debug("empty policy; treating as no enforcement", { nodeId });
      return res;
    },
  };
}
