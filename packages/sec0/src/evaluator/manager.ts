import { createLocalContextualEvaluator, type LocalContextualEvaluatorOptions } from "./local";
import {
  EvaluatorInputSchema,
  EvaluatorModeSchema,
  EvaluatorOutputSchema,
  EvaluatorSourceSchema,
  type EvaluatorEvidence,
  type EvaluatorInput,
  type EvaluatorMode,
  type EvaluatorOutput,
  type EvaluatorPrinciple,
  type EvaluatorSeverity,
  type EvaluatorSource,
} from "./types";

export interface ContextualEvaluatorAdapter {
  evaluate(input: EvaluatorInput): Promise<EvaluatorOutput | null>;
}

export type ContextualEvaluatorFinding = {
  source: "evaluator";
  code: "contextual_evaluator";
  severity: EvaluatorSeverity;
  message: string;
  evidence?: string;
  confidence: number;
  principles: EvaluatorPrinciple[];
  fingerprint: string;
  summary: string;
  reasoning: string;
  snapshot: {
    input: EvaluatorInput;
    output: EvaluatorOutput;
  };
};

export type ContextualEvaluatorManagerConfig = {
  evaluatorSource: EvaluatorSource;
  evaluatorMode: EvaluatorMode;
  debug?: boolean;
  logger?: (event: { level: "debug" | "warn"; message: string; data?: Record<string, unknown> }) => void;
  local?: LocalContextualEvaluatorOptions & {
    adapter?: ContextualEvaluatorAdapter;
  };
  controlPlane?: {
    adapter?: ContextualEvaluatorAdapter;
  };
};

export type ContextualEvaluationExecution = {
  source: Exclude<EvaluatorSource, "disabled">;
  mode: EvaluatorMode;
  output: EvaluatorOutput;
  finding: ContextualEvaluatorFinding;
};

export type ContextualEvaluationScheduleHooks = {
  onResult?: (result: ContextualEvaluationExecution | null) => Promise<void> | void;
};

function logEvent(
  config: ContextualEvaluatorManagerConfig,
  level: "debug" | "warn",
  message: string,
  data?: Record<string, unknown>,
) {
  config.logger?.({ level, message, ...(data ? { data } : {}) });
  if (!config.debug) return;
  const printer = level === "warn" ? console.warn : console.log;
  printer("[sec0-evaluator]", message, data ?? "");
}

export function buildContextualEvaluatorFinding(
  input: EvaluatorInput,
  output: EvaluatorOutput,
): ContextualEvaluatorFinding {
  const evidence =
    output.evidence.length > 0
      ? output.evidence
          .map((item: EvaluatorEvidence) => `${item.label}: ${item.detail}`)
          .join("; ")
          .slice(0, 2000)
      : undefined;
  return {
    source: "evaluator",
    code: "contextual_evaluator",
    severity: output.suggestedSeverity,
    message: output.summary,
    ...(evidence ? { evidence } : {}),
    confidence: output.confidence,
    principles: [...output.principles],
    fingerprint: output.normalizedFingerprint,
    summary: output.summary,
    reasoning: output.reasoning,
    snapshot: {
      input,
      output,
    },
  };
}

export function createContextualEvaluatorManager(config: ContextualEvaluatorManagerConfig) {
  const evaluatorSource = EvaluatorSourceSchema.parse(config.evaluatorSource);
  const evaluatorMode = EvaluatorModeSchema.parse(config.evaluatorMode);

  let adapter: ContextualEvaluatorAdapter | null = null;
  if (evaluatorSource === "local") {
    adapter = config.local?.adapter ?? createLocalContextualEvaluator(config.local);
  } else if (evaluatorSource === "control-plane") {
    adapter = config.controlPlane?.adapter ?? null;
    if (!adapter) {
      throw new Error("[sec0-evaluator] evaluatorSource=\"control-plane\" requires controlPlane.adapter");
    }
  }

  logEvent(config, "debug", "configured", {
    evaluatorSource,
    evaluatorMode,
  });

  const runOnce = async (rawInput: EvaluatorInput): Promise<ContextualEvaluationExecution | null> => {
    if (!adapter || evaluatorSource === "disabled") return null;
    const input = EvaluatorInputSchema.parse(rawInput);
    try {
      const rawOutput = await adapter.evaluate(input);
      if (!rawOutput) return null;
      const output = EvaluatorOutputSchema.parse(rawOutput);
      return {
        source: evaluatorSource,
        mode: evaluatorMode,
        output,
        finding: buildContextualEvaluatorFinding(input, output),
      };
    } catch (error: any) {
      logEvent(config, "warn", "evaluation_failed", {
        evaluatorSource,
        evaluatorMode,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  };

  return {
    source: evaluatorSource,
    mode: evaluatorMode,
    enabled: evaluatorSource !== "disabled",
    async evaluate(input: EvaluatorInput): Promise<ContextualEvaluationExecution | null> {
      return runOnce(input);
    },
    schedule(input: EvaluatorInput, hooks?: ContextualEvaluationScheduleHooks): void {
      if (!adapter || evaluatorSource === "disabled") return;
      void runOnce(input)
        .then((result) => hooks?.onResult?.(result))
        .catch((error: any) => {
          logEvent(config, "warn", "schedule_callback_failed", {
            evaluatorSource,
            evaluatorMode,
            error: error instanceof Error ? error.message : String(error),
          });
        });
    },
  };
}
