import type { ControlPlaneClient } from "./controlPlaneClient";

export type NlJudgeConfig = {
  provider: "openai" | "anthropic";
  apiKey?: string;
  model?: string;
};

export type NlEvalInput = {
  instruction: string;
  text: string;
  threshold: number;
  llmJudge?: NlJudgeConfig;
};

export type NlEvalResult = {
  score: number;
  matched: boolean;
  evidence: string;
};

export function createControlPlaneNlEvaluator(opts: {
  authToken?: string;
  client: ControlPlaneClient;
}): ((input: NlEvalInput) => Promise<NlEvalResult | null>) | null {
  const authToken = String(opts.authToken || "").trim();
  if (!authToken) return null;
  return async (input: NlEvalInput): Promise<NlEvalResult | null> => {
    try {
      const instruction = String(input.instruction || "").trim();
      const textRaw = String(input.text || "");
      const text = textRaw.length > 8000 ? textRaw.slice(0, 8000) : textRaw;
      const threshold = Number.isFinite(input.threshold)
        ? Math.max(0, Math.min(100, Math.round(input.threshold)))
        : 50;
      if (!instruction || !text.trim()) return null;

      const out = await opts.client.evaluateComplianceNl({
        authToken,
        instruction,
        text,
        threshold,
        provider: input.llmJudge?.provider,
        apiKey: input.llmJudge?.apiKey,
        model: input.llmJudge?.model,
      });
      const score = Number.isFinite(out.score) ? Math.max(0, Math.min(100, Math.round(out.score))) : 0;
      return {
        score,
        matched: score >= threshold,
        evidence: typeof out.evidence === "string" ? out.evidence.trim().slice(0, 240) : "",
      };
    } catch {
      return null;
    }
  };
}
