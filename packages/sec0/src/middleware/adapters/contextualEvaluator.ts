import {
  EvaluatorOutputSchema,
  type ContextualEvaluatorAdapter,
  type EvaluatorInput,
  type EvaluatorOutput,
} from "../../evaluator";
import { extractApiKey } from "../apiKeyResolver";
import type { ControlPlaneClient } from "./controlPlaneClient";

export function createControlPlaneContextualEvaluator(opts: {
  auth?: { apiKey?: string; bearerToken?: string };
  client: ControlPlaneClient;
  timeoutMs?: number;
}): ContextualEvaluatorAdapter | null {
  let authToken = "";
  try {
    authToken = extractApiKey({
      "x-api-key": opts.auth?.apiKey,
      authorization: opts.auth?.bearerToken ? `Bearer ${opts.auth.bearerToken}` : undefined,
    } as any);
  } catch {
    authToken = "";
  }
  if (!authToken) return null;

  return {
    async evaluate(input: EvaluatorInput): Promise<EvaluatorOutput | null> {
      return EvaluatorOutputSchema.parse(await opts.client.evaluateContextualEvaluator({
        authToken,
        input,
        timeoutMs: opts.timeoutMs,
      }));
    },
  };
}
