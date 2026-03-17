import type {
  EscalationCreateInput,
  EscalationCreateResult,
  EscalationGetInput,
  EscalationResolveInput,
  EscalationStatusResult,
} from "../core";
import {
  createResolvedConfig,
  invokeHook,
  normalizeTenant,
  sanitizeCreateInput,
  type EscalationErrorEvent,
  type EscalationManager,
  type EscalationManagerConfig,
  type EscalationResolution,
  type EscalationWaitOptions,
  type EscalationCreatedEvent,
} from "./config";
import {
  Sec0EscalationCreateError,
  Sec0EscalationGetError,
  Sec0EscalationResolveError,
  Sec0EscalationWaitError,
} from "./errors";
import { waitForEscalationResolution } from "./waiter";

class DefaultEscalationManager implements EscalationManager {
  private readonly config;
  private readonly inFlightWaits = new Map<string, Promise<EscalationResolution>>();

  constructor(config: EscalationManagerConfig = {}) {
    this.config = createResolvedConfig(config);
  }

  async create(input: EscalationCreateInput): Promise<EscalationCreateResult> {
    const reporter = this.config.reporter;
    if (!reporter) {
      const error = new Sec0EscalationCreateError("Escalation reporter is not configured");
      await invokeHook<EscalationErrorEvent>(this.config.hooks.onError, { operation: "create", error, payload: input });
      throw error;
    }
    const payload = sanitizeCreateInput(input, this.config.defaults, this.config.tenant);
    try {
      const created = await reporter.create(payload);
      if (!created?.id) {
        throw new Sec0EscalationCreateError("Escalation reporter did not return an escalation id");
      }
      await invokeHook<EscalationCreatedEvent>(this.config.hooks.onCreated, { payload, created });
      return created;
    } catch (error: any) {
      const err =
        error instanceof Sec0EscalationCreateError
          ? error
          : new Sec0EscalationCreateError(error?.message || "Escalation create failed");
      await invokeHook<EscalationErrorEvent>(this.config.hooks.onError, { operation: "create", error: err, payload });
      throw err;
    }
  }

  async get(input: EscalationGetInput): Promise<EscalationStatusResult | null> {
    const id = String(input.id || "").trim();
    if (!id) {
      const error = new Sec0EscalationGetError("Escalation id is required");
      await invokeHook<EscalationErrorEvent>(this.config.hooks.onError, { operation: "get", error });
      throw error;
    }
    const resolver = this.config.resolver;
    if (!resolver) {
      const error = new Sec0EscalationGetError("Escalation resolver is not configured");
      await invokeHook<EscalationErrorEvent>(this.config.hooks.onError, { operation: "get", error, escalationId: id });
      throw error;
    }
    try {
      return await resolver.get({
        id,
        ...(normalizeTenant(input.tenant) || this.config.tenant
          ? { tenant: normalizeTenant(input.tenant) || this.config.tenant }
          : {}),
      });
    } catch (error: any) {
      const err = new Sec0EscalationGetError(error?.message || "Escalation get failed", {
        escalationId: id,
      });
      await invokeHook<EscalationErrorEvent>(this.config.hooks.onError, { operation: "get", error: err, escalationId: id });
      throw err;
    }
  }

  async resolve(input: EscalationResolveInput): Promise<EscalationStatusResult | null> {
    const id = String(input.id || "").trim();
    if (!id) {
      const error = new Sec0EscalationResolveError("Escalation id is required");
      await invokeHook<EscalationErrorEvent>(this.config.hooks.onError, { operation: "resolve", error });
      throw error;
    }
    const resolver = this.config.resolver;
    if (!resolver?.resolve) {
      const error = new Sec0EscalationResolveError("Escalation resolver.resolve is not configured");
      await invokeHook<EscalationErrorEvent>(this.config.hooks.onError, {
        operation: "resolve",
        error,
        escalationId: id,
      });
      throw error;
    }
    try {
      return await resolver.resolve({
        id,
        action: input.action,
        ...(typeof input.notes === "string" ? { notes: input.notes } : {}),
        ...(normalizeTenant(input.tenant) || this.config.tenant
          ? { tenant: normalizeTenant(input.tenant) || this.config.tenant }
          : {}),
      });
    } catch (error: any) {
      const err = new Sec0EscalationResolveError(error?.message || "Escalation resolve failed", {
        escalationId: id,
      });
      await invokeHook<EscalationErrorEvent>(this.config.hooks.onError, {
        operation: "resolve",
        error: err,
        escalationId: id,
      });
      throw err;
    }
  }

  async waitForResolution(escalationId: string, options: EscalationWaitOptions = {}): Promise<EscalationResolution> {
    const id = String(escalationId || "").trim();
    if (!id) {
      throw new Sec0EscalationWaitError("Escalation id is required");
    }
    const existing = this.inFlightWaits.get(id);
    if (existing) return existing;

    const wait = waitForEscalationResolution({
      escalationId: id,
      config: this.config,
      options,
      get: (input) => this.get(input),
    }).finally(() => {
      this.inFlightWaits.delete(id);
    });

    this.inFlightWaits.set(id, wait);
    return wait;
  }

  async createAndWait(
    input: EscalationCreateInput,
    options?: EscalationWaitOptions,
  ): Promise<{ created: EscalationCreateResult; resolution: EscalationResolution }> {
    const created = await this.create(input);
    const resolution = await this.waitForResolution(created.id, options);
    return { created, resolution };
  }
}

export function createEscalationManager(config: EscalationManagerConfig = {}): EscalationManager {
  return new DefaultEscalationManager(config);
}
