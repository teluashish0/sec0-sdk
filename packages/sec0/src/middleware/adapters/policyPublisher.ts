import type { PolicyObject } from "../../policy";
import { sha256Hex } from "../../signer";
import * as YAML from "yaml";
import type { ControlPlaneClient } from "./controlPlaneClient";

export async function publishPolicyToControlPlaneIfChanged(opts: {
  tenant?: string;
  level: "gateway" | "middleware";
  policy: PolicyObject;
  authToken?: string;
  urlOverride?: string;
  debug?: boolean;
  client: ControlPlaneClient;
}): Promise<void> {
  const tenant = String(opts.tenant || "").trim();
  if (!tenant) return;
  const authToken = String(opts.authToken || "").trim();
  if (!authToken) {
    debug(!!opts.debug, "skip: no auth configured");
    return;
  }

  debug(!!opts.debug, "begin", { tenant, level: opts.level });
  let latestYaml: string | null = null;
  try {
    const latest = await opts.client.fetchPolicy({
      tenant,
      level: opts.level,
      authToken,
    });
    latestYaml = latest.yaml;
  } catch {
    // Keep original best-effort behavior.
  }

  const desired = (() => {
    try {
      const y = YAML.stringify(opts.policy as any);
      const hasSec = /\bsecurity_level\s*:/i.test(y);
      return (hasSec ? y : `security_level: ${opts.level}\n` + y).trimEnd() + "\n";
    } catch {
      return `security_level: ${opts.level}\n` + JSON.stringify(opts.policy, null, 2);
    }
  })();

  const latestHash = latestYaml ? sha256Hex(Buffer.from(latestYaml.trim())) : null;
  const desiredHash = sha256Hex(Buffer.from(desired.trim()));
  debug(!!opts.debug, "compare", { equal: latestYaml?.trim() === desired.trim(), latestHash, desiredHash });
  if (latestYaml == null || latestYaml.trim() !== desired.trim()) {
    await opts.client.putPolicy({
      tenant,
      level: opts.level,
      authToken,
      yaml: desired,
      urlOverride: opts.urlOverride,
    });
    debug(!!opts.debug, "published");
  } else {
    debug(!!opts.debug, "up-to-date; no write");
  }
}

function debug(enabled: boolean, msg: string, extra?: unknown) {
  if (!enabled) return;
  try {
    console.log("[sec0-middleware][policy-sync]", msg, extra ?? "");
  } catch {}
}
