import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { createHash } from "node:crypto";
import { parsePolicyYaml } from "../policy";
import { GuardConfigError, GuardPolicyInvalidError, GuardPolicyUnavailableError } from "./errors";
import type {
  GuardInput,
  GuardLocalPolicyProviderConfig,
  GuardMode,
  GuardPolicyInput,
  GuardPolicyProvider,
  GuardProviderConfig,
  GuardProviderPrecedence,
  GuardProviderSnapshot,
  GuardRemotePolicyProviderConfig,
  GuardRuntimeContext,
  Sec0GuardConfig,
} from "./types";

type CachedPolicy = {
  snapshot: GuardProviderSnapshot;
  loadedAtMs: number;
  mtimeMs?: number;
};

function stableHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value ?? null)).digest("hex");
}

function asPositiveInt(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  const n = Math.floor(parsed);
  return n > 0 ? n : fallback;
}

function parsePolicyFile(filePath: string): GuardPolicyInput {
  const absolutePath = path.resolve(filePath);
  const raw = fs.readFileSync(absolutePath, "utf8");
  if (!raw.trim()) {
    throw new GuardPolicyInvalidError("Guard policy file is empty", { policyPath: absolutePath });
  }
  const ext = path.extname(absolutePath).toLowerCase();
  if (ext === ".json") {
    try {
      return JSON.parse(raw) as GuardPolicyInput;
    } catch (error: any) {
      throw new GuardPolicyInvalidError("Failed to parse guard JSON policy", {
        policyPath: absolutePath,
        cause: error?.message || String(error),
      });
    }
  }

  try {
    return parsePolicyYaml(raw);
  } catch {
    try {
      const parsed = YAML.parse(raw);
      if (!parsed || typeof parsed !== "object") {
        throw new Error("yaml_did_not_parse_object");
      }
      return parsed as GuardPolicyInput;
    } catch (error: any) {
      throw new GuardPolicyInvalidError("Failed to parse guard YAML policy", {
        policyPath: absolutePath,
        cause: error?.message || String(error),
      });
    }
  }
}

function isSnapshot(value: unknown): value is GuardProviderSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return typeof record.hash === "string" && "policy" in record;
}

class LocalPolicyProvider implements GuardPolicyProvider {
  private cache: CachedPolicy | null = null;
  private readonly cacheTtlMs: number;
  private readonly policyObject?: GuardPolicyInput;
  private readonly policyPath?: string;

  constructor(config: GuardLocalPolicyProviderConfig) {
    this.cacheTtlMs = asPositiveInt(config.cacheTtlMs, 1_000);
    this.policyObject = config.policy;
    this.policyPath = typeof config.policyPath === "string" && config.policyPath.trim()
      ? path.resolve(config.policyPath.trim())
      : undefined;
  }

  private loadFromPath(): GuardProviderSnapshot {
    if (!this.policyPath) {
      throw new GuardPolicyUnavailableError("Local guard policy path is not configured");
    }
    if (!fs.existsSync(this.policyPath)) {
      throw new GuardPolicyUnavailableError("Local guard policy file does not exist", {
        policyPath: this.policyPath,
      });
    }
    const stat = fs.statSync(this.policyPath);
    if (this.cache && this.cache.mtimeMs === stat.mtimeMs && Date.now() - this.cache.loadedAtMs < this.cacheTtlMs) {
      return this.cache.snapshot;
    }
    const policy = parsePolicyFile(this.policyPath);
    const snapshot: GuardProviderSnapshot = {
      policy,
      hash: stableHash(policy),
      source: "local",
    };
    this.cache = {
      snapshot,
      loadedAtMs: Date.now(),
      mtimeMs: stat.mtimeMs,
    };
    return snapshot;
  }

  private loadFromObject(): GuardProviderSnapshot {
    if (!this.policyObject) {
      throw new GuardPolicyUnavailableError("Local guard policy object is not configured");
    }
    if (this.cache && Date.now() - this.cache.loadedAtMs < this.cacheTtlMs) {
      return this.cache.snapshot;
    }
    const snapshot: GuardProviderSnapshot = {
      policy: this.policyObject,
      hash: stableHash(this.policyObject),
      source: "local",
    };
    this.cache = {
      snapshot,
      loadedAtMs: Date.now(),
    };
    return snapshot;
  }

  async getPolicy(): Promise<GuardProviderSnapshot> {
    if (this.policyPath) return this.loadFromPath();
    return this.loadFromObject();
  }
}

class RemotePolicyProvider implements GuardPolicyProvider {
  constructor(private readonly config: GuardRemotePolicyProviderConfig) {}

  async getPolicy(input: GuardInput): Promise<GuardProviderSnapshot> {
    const result = await this.config.getPolicy(input);
    if (isSnapshot(result)) {
      return {
        ...result,
        source: result.source === "local" ? "remote" : result.source,
      };
    }
    return {
      policy: result,
      hash: stableHash(result),
      source: "remote",
    };
  }
}

class CompositePolicyProvider implements GuardPolicyProvider {
  private lastRemoteSnapshot: GuardProviderSnapshot | null = null;

  constructor(private readonly config: {
    precedence: GuardProviderPrecedence;
    local?: GuardPolicyProvider;
    remote?: GuardPolicyProvider;
    runtime: GuardRuntimeContext;
  }) {}

  private async readRemote(input: GuardInput): Promise<GuardProviderSnapshot> {
    if (!this.config.remote) throw new GuardPolicyUnavailableError("Remote guard provider is not configured");
    const snapshot = await this.config.remote.getPolicy(input);
    this.lastRemoteSnapshot = snapshot;
    return snapshot;
  }

  private async readLocal(input: GuardInput): Promise<GuardProviderSnapshot> {
    if (!this.config.local) throw new GuardPolicyUnavailableError("Local guard provider is not configured");
    return this.config.local.getPolicy(input);
  }

  async getPolicy(input: GuardInput): Promise<GuardProviderSnapshot> {
    if (this.config.precedence === "local-first") {
      try {
        return await this.readLocal(input);
      } catch (localError: any) {
        const remote = await this.readRemote(input);
        return {
          ...remote,
          source: "remote",
          fallbackReason: `local_unavailable:${localError?.message || "unknown"}`,
        };
      }
    }

    try {
      return await this.readRemote(input);
    } catch (remoteError: any) {
      if (this.lastRemoteSnapshot) {
        return {
          ...this.lastRemoteSnapshot,
          source: "remote-cache",
          fallbackReason: `remote_failed_using_cache:${remoteError?.message || "unknown"}`,
        };
      }
      try {
        const local = await this.readLocal(input);
        return {
          ...local,
          source: "local-fallback",
          fallbackReason: `remote_failed_using_local:${remoteError?.message || "unknown"}`,
        };
      } catch (localError: any) {
        this.config.runtime.log({
          level: "error",
          message: "guard policy resolution failed",
          data: {
            remoteError: remoteError?.message || String(remoteError),
            localError: localError?.message || String(localError),
          },
        });
        throw new GuardPolicyUnavailableError("Unable to resolve guard policy from remote or local provider", {
          remoteError: remoteError?.message || String(remoteError),
          localError: localError?.message || String(localError),
        });
      }
    }
  }
}

export function resolveGuardMode(config: Sec0GuardConfig): GuardMode {
  if (config.mode === "standalone" || config.mode === "dashboard" || config.mode === "hybrid") {
    return config.mode;
  }
  const hasRemote = !!config.provider?.remote;
  const hasLocal = !!config.provider?.local;
  if (hasRemote && hasLocal) return "hybrid";
  if (hasRemote) return "dashboard";
  return "standalone";
}

export function validateProviderConfig(mode: GuardMode, provider: GuardProviderConfig | undefined): {
  precedence: GuardProviderPrecedence;
  local?: GuardLocalPolicyProviderConfig;
  remote?: GuardRemotePolicyProviderConfig;
} {
  const precedence: GuardProviderPrecedence =
    provider?.precedence === "local-first" || provider?.precedence === "remote-first"
      ? provider.precedence
      : "remote-first";

  if (mode === "standalone") {
    if (!provider?.local?.policy && !provider?.local?.policyPath) {
      throw new GuardConfigError(
        "standalone mode requires provider.local.policy or provider.local.policyPath",
      );
    }
    return { precedence, local: provider.local };
  }

  if (mode === "dashboard") {
    if (!provider?.remote) {
      throw new GuardConfigError("dashboard mode requires provider.remote");
    }
    return { precedence, remote: provider.remote };
  }

  if (!provider?.remote) {
    throw new GuardConfigError("hybrid mode requires provider.remote");
  }
  if (!provider?.local?.policy && !provider?.local?.policyPath) {
    throw new GuardConfigError("hybrid mode requires provider.local.policy or provider.local.policyPath for fallback");
  }
  return { precedence, local: provider.local, remote: provider.remote };
}

export function createGuardPolicyProvider(opts: {
  mode: GuardMode;
  provider?: GuardProviderConfig;
  runtime: GuardRuntimeContext;
}): GuardPolicyProvider {
  const resolved = validateProviderConfig(opts.mode, opts.provider);
  const local = resolved.local ? new LocalPolicyProvider(resolved.local) : undefined;
  const remote = resolved.remote ? new RemotePolicyProvider(resolved.remote) : undefined;

  if (opts.mode === "standalone") {
    if (!local) throw new GuardConfigError("standalone mode local provider could not be initialized");
    return local;
  }

  if (opts.mode === "dashboard") {
    if (!remote) throw new GuardConfigError("dashboard mode remote provider could not be initialized");
    return remote;
  }

  return new CompositePolicyProvider({
    precedence: resolved.precedence,
    local,
    remote,
    runtime: opts.runtime,
  });
}
