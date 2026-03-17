import { type GuardEscalationResolution } from "../../guard";
import type { EscalationReporter, EscalationResolver } from "../../core/contracts";
import { createEscalationManager, type EscalationManager } from "../../escalation";
import type { MoltbotMessageSendingResult } from "./moltbot";

export type MoltbotEscalationMode = "human" | "auto-approve" | "auto-reject" | "off";

export type MoltbotEscalationManagerConfig = {
  escalationMode?: MoltbotEscalationMode;
  tenant?: string;
  manager?: EscalationManager;
  waitForResolution?: boolean;
  timeoutMs?: number;
  controlPlaneTimeoutMs?: number;
  pollIntervalMs?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
  ttlSeconds?: number;
  timeoutAction?: "auto_approve" | "auto_reject";
  apiKey?: string;
  controlPlaneUrl?: string;
  reporter?: EscalationReporter;
  resolver?: EscalationResolver;
  onEscalationCreated?: (event: {
    escalationId: string;
    violation: string;
    message: string;
    severity: "low" | "medium" | "high" | "critical";
  }) => Promise<void> | void;
  onEscalationResolved?: (event: {
    escalationId: string;
    resolution: GuardEscalationResolution;
  }) => Promise<void> | void;
  onEscalationError?: (event: {
    error: Error;
    violation?: string;
  }) => Promise<void> | void;
};

export type MoltbotEscalationHandleInput = {
  gateResult?: MoltbotMessageSendingResult | void;
  content?: string;
  nodeId?: string;
  agentRef?: string;
  metadata?: Record<string, unknown>;
  onEscalationCreated?: (event: {
    escalationId: string;
    violation: string;
    message: string;
    severity: "low" | "medium" | "high" | "critical";
  }) => Promise<void> | void;
  onEscalationResolved?: (event: {
    escalationId: string;
    resolution: GuardEscalationResolution;
  }) => Promise<void> | void;
  onEscalationError?: (event: {
    error: Error;
    violation?: string;
  }) => Promise<void> | void;
};

export type MoltbotEscalationHandleResult = {
  allow: boolean;
  status: "allow" | "blocked" | "approved" | "rejected" | "expired" | "timeout" | "pending" | "create_failed";
  escalationId?: string;
  resolution?: GuardEscalationResolution;
  violation?: string;
  errorMessage?: string;
};

function normalizeEscalationMode(raw: unknown): MoltbotEscalationMode {
  const mode = String(raw || "human").trim().toLowerCase();
  if (mode === "human" || mode === "auto-approve" || mode === "auto-reject" || mode === "off") return mode;
  return "human";
}

function normalizeSeverity(raw: unknown): "low" | "medium" | "high" | "critical" {
  const severity = String(raw || "").trim().toLowerCase();
  if (severity === "low" || severity === "medium" || severity === "high" || severity === "critical") return severity;
  return "medium";
}

function severityWeight(raw: unknown): number {
  const severity = normalizeSeverity(raw);
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  return 1;
}

function isRuleBackedEscalationFinding(finding: NonNullable<MoltbotMessageSendingResult["escalationDetails"]>["findings"][number] | null | undefined) {
  if (!finding || typeof finding !== "object") return false;
  const source = String((finding as any).source || "").trim().toLowerCase();
  if (source === "evaluator") return false;
  return Boolean(
    (typeof (finding as any).ruleId === "string" && (finding as any).ruleId.trim()) ||
    (typeof (finding as any).policyId === "string" && (finding as any).policyId.trim()) ||
    (typeof (finding as any).packId === "string" && (finding as any).packId.trim())
  );
}

function isNonEvaluatorEscalationFinding(
  finding: NonNullable<MoltbotMessageSendingResult["escalationDetails"]>["findings"][number] | null | undefined,
) {
  if (!finding || typeof finding !== "object") return false;
  const source = String((finding as any).source || "").trim().toLowerCase();
  const code = String((finding as any).code || "").trim().toLowerCase();
  return source !== "evaluator" && code !== "contextual_evaluator";
}

function strongestEscalationFinding(details: MoltbotMessageSendingResult["escalationDetails"]) {
  if (!Array.isArray(details?.findings) || details.findings.length === 0) return null;
  const candidates =
    String(details?.findingSource || "").trim().toLowerCase() === "rule"
      ? details.findings.filter((finding) => isNonEvaluatorEscalationFinding(finding))
      : details.findings;
  const pool = candidates.length ? candidates : details.findings;
  return pool.reduce((best, current) => {
    if (!best) return current;

    const bestHasRule = isRuleBackedEscalationFinding(best);
    const currentHasRule = isRuleBackedEscalationFinding(current);
    if (bestHasRule !== currentHasRule) return currentHasRule ? current : best;

    const bestWeight = severityWeight(best.severity);
    const currentWeight = severityWeight(current.severity);
    if (currentWeight !== bestWeight) return currentWeight > bestWeight ? current : best;

    return best;
  }, pool[0] ?? null);
}

function resolutionStatusToResultStatus(
  status: GuardEscalationResolution["status"],
): MoltbotEscalationHandleResult["status"] {
  if (status === "approved") return "approved";
  if (status === "rejected") return "rejected";
  if (status === "expired") return "expired";
  return "timeout";
}

export function createMoltbotEscalationManager(config: MoltbotEscalationManagerConfig = {}) {
  const mode = normalizeEscalationMode(config.escalationMode);
  const apiKey = String(config.apiKey || "").trim();
  const controlPlaneUrl = String(config.controlPlaneUrl || "").trim();
  const tenant = typeof config.tenant === "string" && config.tenant.trim() ? config.tenant.trim() : undefined;
  const timeoutMs = Number.isFinite(Number(config.timeoutMs)) ? Math.max(1, Math.floor(Number(config.timeoutMs))) : 5 * 60 * 1000;
  const controlPlaneTimeoutMs = Number.isFinite(Number(config.controlPlaneTimeoutMs))
    ? Math.max(1000, Math.floor(Number(config.controlPlaneTimeoutMs)))
    : 8000;
  const pollIntervalMs = Number.isFinite(Number(config.pollIntervalMs))
    ? Math.max(200, Math.floor(Number(config.pollIntervalMs)))
    : 2000;
  const maxRetries = Number.isFinite(Number(config.maxRetries)) ? Math.max(0, Math.floor(Number(config.maxRetries))) : 3;
  const retryBackoffMs = Number.isFinite(Number(config.retryBackoffMs))
    ? Math.max(50, Math.floor(Number(config.retryBackoffMs)))
    : 250;
  const ttlSeconds = Number.isFinite(Number(config.ttlSeconds)) ? Math.max(1, Math.floor(Number(config.ttlSeconds))) : undefined;
  const timeoutAction =
    config.timeoutAction === "auto_approve" || config.timeoutAction === "auto_reject"
      ? config.timeoutAction
      : undefined;
  const shouldWaitForResolution = config.waitForResolution !== false;
  const manager =
    config.manager ||
    createEscalationManager({
      tenant,
      reporter: config.reporter,
      resolver: config.resolver,
      ...(apiKey ? { apiKey } : {}),
      ...(controlPlaneUrl ? { controlPlaneUrl } : {}),
      controlPlaneTimeoutMs,
      timeoutMs,
      pollIntervalMs,
      maxRetries,
      retryBackoffMs,
      ...((typeof ttlSeconds === "number" || timeoutAction)
        ? {
            defaults: {
              ...(typeof ttlSeconds === "number" ? { ttlSeconds } : {}),
              ...(timeoutAction ? { timeoutAction } : {}),
            },
          }
        : {}),
    });

  return {
    async handle(input: MoltbotEscalationHandleInput): Promise<MoltbotEscalationHandleResult> {
      const gateResult = input.gateResult;
      if (!gateResult) return { allow: true, status: "allow" };
      if (gateResult.cancel) return { allow: false, status: "blocked" };
      if (!(gateResult.escalate && gateResult.escalationDetails)) return { allow: true, status: "allow" };

      const details = gateResult.escalationDetails;
      const finding = strongestEscalationFinding(details);
      const violation =
        typeof details.violation === "string" && details.violation.trim() ? details.violation.trim() : "policy_violation";
      const message =
        typeof finding?.message === "string" && finding.message.trim()
          ? finding.message.trim()
          : "Policy violation detected";
      const severity = normalizeSeverity(finding?.severity);
      const ruleId = typeof finding?.ruleId === "string" && finding.ruleId.trim() ? finding.ruleId.trim() : undefined;

      if (mode === "off" || mode === "auto-reject") {
        return { allow: false, status: "rejected", violation };
      }
      if (mode === "auto-approve") {
        return { allow: true, status: "approved", violation };
      }
      let createdEscalationId: string | undefined;
      try {
        const created = await manager.create({
          ...(tenant ? { tenant } : {}),
          content: String(details.content || input.content || ""),
          violation,
          ...(ruleId ? { ruleId } : {}),
          message,
          severity,
          ...(input.nodeId ? { nodeId: input.nodeId } : {}),
          ...(input.agentRef ? { agentRef: input.agentRef } : {}),
          ...(details.findingSource ? { findingSource: details.findingSource } : {}),
          ...(details.evaluatorFingerprint ? { evaluatorFingerprint: details.evaluatorFingerprint } : {}),
          ...(typeof details.evaluatorConfidence === "number"
            ? { evaluatorConfidence: details.evaluatorConfidence }
            : {}),
          ...(Array.isArray(details.evaluatorPrinciples)
            ? { evaluatorPrinciples: details.evaluatorPrinciples }
            : {}),
          ...(details.evaluatorSnapshot ? { evaluatorSnapshot: details.evaluatorSnapshot } : {}),
          metadata: {
            ...(input.metadata || {}),
            findings: Array.isArray(details.findings) ? details.findings : [],
          },
        });
        if (!created?.id) {
          const err = new Error("Escalation reporter did not return an escalation id");
          await Promise.resolve(config.onEscalationError?.({ error: err, violation }));
          await Promise.resolve(input.onEscalationError?.({ error: err, violation }));
          return { allow: false, status: "create_failed", violation, errorMessage: err.message };
        }
        createdEscalationId = created.id;

        await Promise.resolve(
          config.onEscalationCreated?.({
            escalationId: created.id,
            violation,
            message,
            severity,
          }),
        );
        await Promise.resolve(
          input.onEscalationCreated?.({
            escalationId: created.id,
            violation,
            message,
            severity,
          }),
        );

        if (!shouldWaitForResolution) {
          return { allow: false, status: "pending", escalationId: created.id, violation };
        }

        const resolution = await manager.waitForResolution(created.id, {
          ...(tenant ? { tenant } : {}),
          timeoutMs,
          pollIntervalMs,
          maxRetries,
          retryBackoffMs,
        });
        await Promise.resolve(
          config.onEscalationResolved?.({
            escalationId: created.id,
            resolution,
          }),
        );
        await Promise.resolve(
          input.onEscalationResolved?.({
            escalationId: created.id,
            resolution,
          }),
        );

        if (resolution.status === "approved") {
          return { allow: true, status: "approved", escalationId: created.id, resolution, violation };
        }
        if (resolution.status === "timeout") {
          return { allow: false, status: "pending", escalationId: created.id, resolution, violation };
        }
        return {
          allow: false,
          status: resolutionStatusToResultStatus(resolution.status),
          escalationId: created.id,
          resolution,
          violation,
        };
      } catch (error: any) {
        const err = error instanceof Error ? error : new Error(String(error));
        await Promise.resolve(config.onEscalationError?.({ error: err, violation }));
        await Promise.resolve(input.onEscalationError?.({ error: err, violation }));
        if (!createdEscalationId) {
          return { allow: false, status: "create_failed", violation, errorMessage: err.message };
        }
        return {
          allow: false,
          status: "rejected",
          escalationId: createdEscalationId,
          violation,
          errorMessage: err.message,
        };
      }
    },
  };
}
