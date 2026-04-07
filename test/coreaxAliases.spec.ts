import { describe, expect, it } from "vitest";

import {
  CoreaxAppender,
  CoreaxEscalationAbortError,
  CoreaxEscalationCreateError,
  CoreaxEscalationError,
  CoreaxEscalationGetError,
  CoreaxEscalationResolveError,
  CoreaxEscalationWaitError,
  Sec0Appender,
  Sec0EscalationAbortError,
  Sec0EscalationCreateError,
  Sec0EscalationError,
  Sec0EscalationGetError,
  Sec0EscalationResolveError,
  Sec0EscalationWaitError,
  createCoreaxGuard,
  createSec0Guard,
} from "../src";
import { CoreaxGuardError, Sec0GuardError } from "../src/guard";
import {
  createCoreaxAuditSink,
  createSec0AuditSink,
  createHostedCoreaxPreset,
  createHostedSec0Preset,
  createLocalCoreaxPreset,
  createLocalSec0Preset,
  coreaxHostedMiddleware,
  coreaxLocalMiddleware,
  coreaxSecurityMiddleware,
  getCoreaxMeta,
  getSec0Meta,
  initializeCoreaxMiddleware,
  initializeSec0Middleware,
  sec0HostedMiddleware,
  sec0LocalMiddleware,
  sec0SecurityMiddleware,
  withCoreaxMeta,
  withSec0Meta,
} from "../src/middleware";
import {
  coreax,
  coreaxAgent,
  coreaxDecorators,
  coreaxGateway,
  coreaxMiddleware,
  coreaxOrchestrator,
  coreaxServer,
  coreaxSkill,
  coreaxTool,
  getCoreaxAppConfig,
  getCoreaxDirectories,
  getSec0AppConfig,
  getSec0Directories,
  initCoreax,
  initSec0,
  initializeCoreaxApp,
  initializeSec0App,
  loadAndInitCoreax,
  loadAndInitSec0,
  sec0,
  sec0Agent,
  sec0Decorators,
  seedCoreaxRun,
  seedSec0Run,
} from "../src/instrumentation";

describe("Coreax aliases in the canonical package", () => {
  it("keeps guard and middleware aliases wired to the existing implementations", () => {
    expect(createCoreaxGuard).toBe(createSec0Guard);
    expect(coreaxSecurityMiddleware).toBe(sec0SecurityMiddleware);
    expect(coreaxLocalMiddleware).toBe(sec0LocalMiddleware);
    expect(coreaxHostedMiddleware).toBe(sec0HostedMiddleware);
    expect(initializeCoreaxMiddleware).toBe(initializeSec0Middleware);
    expect(withCoreaxMeta).toBe(withSec0Meta);
    expect(getCoreaxMeta).toBe(getSec0Meta);
    expect(createLocalCoreaxPreset).toBe(createLocalSec0Preset);
    expect(createHostedCoreaxPreset).toBe(createHostedSec0Preset);
    expect(createCoreaxAuditSink).toBe(createSec0AuditSink);
  });

  it("keeps instrumentation aliases available alongside the legacy sec0 names", () => {
    expect(initCoreax).toBe(initSec0);
    expect(loadAndInitCoreax).toBe(loadAndInitSec0);
    expect(getCoreaxAppConfig).toBe(getSec0AppConfig);
    expect(initializeCoreaxApp).toBe(initializeSec0App);
    expect(getCoreaxDirectories).toBe(getSec0Directories);
    expect(seedCoreaxRun).toBe(seedSec0Run);

    expect(coreaxAgent).toBe(sec0Agent);
    expect(coreax.agent).toBe(coreaxAgent);
    expect(coreax.orchestrator).toBe(coreaxOrchestrator);
    expect(coreax.gateway).toBe(coreaxGateway);
    expect(coreax.server).toBe(coreaxServer);
    expect(coreax.middleware).toBe(coreaxMiddleware);
    expect(coreax.tool).toBe(coreaxTool);
    expect(coreax.skill).toBe(coreaxSkill);

    expect(coreaxDecorators["coreax-agent"]).toBe(coreaxAgent);
    expect(coreaxDecorators["coreax-orchestrator"]).toBe(coreaxOrchestrator);
    expect(coreaxDecorators["coreax-gateway"]).toBe(coreaxGateway);
    expect(coreaxDecorators["coreax-server"]).toBe(coreaxServer);
    expect(coreaxDecorators["coreax-middleware"]).toBe(coreaxMiddleware);
    expect(coreaxDecorators["coreax-tool"]).toBe(coreaxTool);
    expect(coreaxDecorators["coreax-skill"]).toBe(coreaxSkill);

    expect(sec0.agent).toBe(sec0Agent);
    expect(sec0Decorators["sec0-agent"]).toBe(sec0Agent);
  });

  it("keeps public class and error aliases wired to the existing implementations", () => {
    expect(CoreaxAppender).toBe(Sec0Appender);
    expect(CoreaxGuardError).toBe(Sec0GuardError);
    expect(CoreaxEscalationError).toBe(Sec0EscalationError);
    expect(CoreaxEscalationCreateError).toBe(Sec0EscalationCreateError);
    expect(CoreaxEscalationGetError).toBe(Sec0EscalationGetError);
    expect(CoreaxEscalationResolveError).toBe(Sec0EscalationResolveError);
    expect(CoreaxEscalationWaitError).toBe(Sec0EscalationWaitError);
    expect(CoreaxEscalationAbortError).toBe(Sec0EscalationAbortError);
  });
});
