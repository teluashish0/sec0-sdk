import YAML from "yaml";
import type { PolicyObject } from "../policy";
import { createSec0AuditSink } from "./adapters/auditSink";
import { createControlPlaneApprovalVerifier, createNoopApprovalVerifier } from "./adapters/approvalVerifier";
import { createControlPlaneClient, type ControlPlaneClient } from "./adapters/controlPlaneClient";
import { createControlPlaneEscalationReporter, createNoopEscalationReporter } from "./adapters/escalationReporter";
import { createControlPlanePolicyProvider, createStaticPolicyProvider } from "./adapters/policyProvider";
import { createRuntimeInvoker } from "./adapters/runtimeInvoker";
import { resolveControlPlaneUrl } from "./controlPlane";
import { isControlPlanePolicySource, type ControlPlanePolicySource } from "./controlPlanePolicy";
import type { MiddlewareOptions } from "./index";

export type LocalSec0PresetOptions = Omit<MiddlewareOptions, "adapters" | "policy"> & {
  policy: PolicyObject | string;
};

export type HostedSec0PresetOptions = Omit<MiddlewareOptions, "adapters">;

export type MiddlewarePresetDependencies = {
  controlPlaneClient?: ControlPlaneClient;
};

function normalizePresetPolicyObject(input: PolicyObject): PolicyObject {
  const obj: any = input && typeof input === "object" ? input : {};
  const enforcement: any = obj.enforcement && typeof obj.enforcement === "object" ? obj.enforcement : {};
  if (!Array.isArray(enforcement.deny_on)) enforcement.deny_on = [];
  if (enforcement.escalate_on !== undefined && !Array.isArray(enforcement.escalate_on)) {
    enforcement.escalate_on = [];
  }
  obj.enforcement = enforcement;
  return obj as PolicyObject;
}

function parsePresetPolicy(policy: PolicyObject | string): PolicyObject {
  if (typeof policy === "string") {
    try {
      const parsed = YAML.parse(policy);
      return normalizePresetPolicyObject(parsed as PolicyObject);
    } catch (err: any) {
      throw new Error(`[sec0-middleware] failed to parse preset policy yaml: ${err?.message || err}`);
    }
  }
  return normalizePresetPolicyObject(policy);
}

export function createLocalSec0Preset(opts: LocalSec0PresetOptions): MiddlewareOptions {
  const policy = parsePresetPolicy(opts.policy);
  return {
    ...opts,
    policy,
    adapters: {
      policyProvider: createStaticPolicyProvider(policy),
      approvalVerifier: createNoopApprovalVerifier(),
      escalationReporter: createNoopEscalationReporter(),
      runtimeInvoker: createRuntimeInvoker({
        ...(opts.runtime?.enforcement || {}),
        mode: "local",
      }),
      auditSink: createSec0AuditSink({ config: opts.sec0, signer: opts.signer }),
    },
  };
}

export function createHostedSec0Preset(
  opts: HostedSec0PresetOptions,
  deps?: MiddlewarePresetDependencies,
): MiddlewareOptions {
  const controlPlaneUrl = resolveControlPlaneUrl(opts.controlPlaneUrl);
  const controlPlaneClient = deps?.controlPlaneClient ?? createControlPlaneClient({ baseUrl: controlPlaneUrl });
  const policySource = isControlPlanePolicySource(opts.policy) ? (opts.policy as ControlPlanePolicySource) : null;
  const policyProvider = policySource
    ? createControlPlanePolicyProvider({
        source: policySource,
        controlPlaneUrl,
        auth: opts.auth,
        debug: opts.runtime?.debug?.policySync === true,
        client: controlPlaneClient,
      })
    : createStaticPolicyProvider(parsePresetPolicy(opts.policy as PolicyObject | string));
  const approvalVerifier = opts.auth
    ? createControlPlaneApprovalVerifier({ auth: opts.auth, client: controlPlaneClient })
    : createNoopApprovalVerifier();
  const escalationReporter = opts.auth
    ? createControlPlaneEscalationReporter({ auth: opts.auth, client: controlPlaneClient })
    : createNoopEscalationReporter();

  return {
    ...opts,
    controlPlaneUrl,
    adapters: {
      policyProvider,
      approvalVerifier,
      escalationReporter,
      runtimeInvoker: createRuntimeInvoker(opts.runtime?.enforcement),
      auditSink: createSec0AuditSink({ config: opts.sec0, signer: opts.signer }),
    },
  };
}
