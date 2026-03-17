import { canonicalize, sha256Hex } from "../../signer";
import type { PolicyObject } from "../../policy";
import type { PolicyProvider } from "../../core/contracts";
import {
  createControlPlanePolicyManager,
  type ControlPlanePolicySource,
} from "../controlPlanePolicy";
import type { ControlPlaneClient } from "./controlPlaneClient";

export function createStaticPolicyProvider(policy: PolicyObject): PolicyProvider {
  const hash = (() => {
    try {
      return sha256Hex(Buffer.from(canonicalize(policy as any)));
    } catch {
      return "static";
    }
  })();
  return {
    async getPolicy() {
      return { policy, hash };
    },
  };
}

export function createControlPlanePolicyProvider(opts: {
  source: ControlPlanePolicySource;
  controlPlaneUrl?: string;
  auth?: { apiKey?: string; bearerToken?: string };
  debug?: boolean;
  client?: ControlPlaneClient;
}): PolicyProvider {
  const manager = createControlPlanePolicyManager({
    source: opts.source,
    controlPlaneUrl: opts.controlPlaneUrl,
    auth: opts.auth,
    debug: opts.debug,
    client: opts.client,
  });
  return {
    async getPolicy(context) {
      const resolved = await manager.getPolicy({ nodeId: context?.nodeId });
      return {
        policy: resolved.policy,
        hash: resolved.hash,
        tenant: resolved.tenant,
        env: resolved.env,
        clientName: resolved.clientName,
        clientVersion: resolved.clientVersion,
      };
    },
  };
}
