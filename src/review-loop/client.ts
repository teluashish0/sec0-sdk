import { randomUUID } from "node:crypto";

import type {
  ActionProposal,
  ExecutionResult,
  HumanResolution,
  OutcomeRecord,
  PendingReview,
  PreferenceExample,
  ReplayEventRow,
  ResolveReviewInput,
  ReviewJsonObject,
  ReviewJsonValue,
  ReviewLoopWaitOptions,
  RewardOutcomeRow,
  ReviewSubmission,
} from "./types";

export interface ReviewLoopClient {
  submitProposal(input: { proposal: ActionProposal }): Promise<ReviewSubmission>;
  listPendingReviews(): Promise<PendingReview[]>;
  getHumanResolution(proposalId: string): Promise<HumanResolution | null>;
  waitForHumanResolution(
    proposalId: string,
    options?: ReviewLoopWaitOptions,
  ): Promise<HumanResolution | null>;
  resolveReview(input: ResolveReviewInput): Promise<HumanResolution>;
  reportExecution(result: ExecutionResult): Promise<ExecutionResult>;
  reportOutcome(result: OutcomeRecord): Promise<OutcomeRecord>;
  exportPreferenceExamples(): Promise<PreferenceExample[]>;
  exportRewardOutcomeRows(): Promise<RewardOutcomeRow[]>;
  exportReplayRows(): Promise<ReplayEventRow[]>;
}

export interface HttpReviewLoopClientConfig {
  baseUrl: string;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
}

export interface ReviewedActionSummary {
  status?: string;
  result_summary?: string | null;
  output_reference?: string | null;
  metadata?: ReviewJsonObject;
}

export interface ExecuteReviewedActionOptions<
  TArgs extends ReviewJsonObject,
  TResult,
> {
  client: ReviewLoopClient;
  proposal: ActionProposal;
  execute(args: TArgs): Promise<TResult> | TResult;
  waitForResolution?: boolean | ReviewLoopWaitOptions;
  summarizeResult?(result: TResult): ReviewedActionSummary;
  now?: () => string;
}

export interface ReviewedActionResult<TResult> {
  submission: ReviewSubmission;
  human_resolution?: HumanResolution | null;
  execution_result: ExecutionResult;
  value?: TResult;
}

function asObject(value: unknown): ReviewJsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as ReviewJsonObject)
    : {};
}

function summarizeValue(value: unknown): string {
  if (typeof value === "string") {
    return value.slice(0, 500);
  }
  try {
    return JSON.stringify(value).slice(0, 500);
  } catch {
    return String(value).slice(0, 500);
  }
}

export function normalizeActionProposal(
  proposal: Omit<ActionProposal, "proposal_id" | "created_at"> &
    Partial<Pick<ActionProposal, "proposal_id" | "created_at">>,
  now: () => string = () => new Date().toISOString(),
): ActionProposal {
  return {
    ...proposal,
    proposal_id: proposal.proposal_id || randomUUID(),
    trace_id: proposal.trace_id || null,
    arguments: asObject(proposal.arguments),
    observation_context: asObject(proposal.observation_context),
    metadata: asObject(proposal.metadata),
    created_at: proposal.created_at || now(),
  };
}

export function applyHumanResolutionArguments(
  originalArguments: ReviewJsonObject,
  resolution?: HumanResolution | null,
): ReviewJsonObject {
  if (resolution?.decision === "edit" && resolution.edited_arguments) {
    return resolution.edited_arguments;
  }
  return originalArguments;
}

export class HttpReviewLoopClient implements ReviewLoopClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly fetchImpl: typeof fetch;

  constructor(config: HttpReviewLoopClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.headers = config.headers || {};
    this.fetchImpl = config.fetchImpl || fetch;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        "content-type": "application/json",
        ...this.headers,
        ...(init?.headers || {}),
      },
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`review_loop_http_${response.status}:${text}`);
    }
    return (await response.json()) as T;
  }

  submitProposal(input: { proposal: ActionProposal }): Promise<ReviewSubmission> {
    return this.request("/review-loop/proposals", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listPendingReviews(): Promise<PendingReview[]> {
    const payload = await this.request<{ pending: PendingReview[] }>("/review-loop/pending");
    return payload.pending || [];
  }

  async getHumanResolution(proposalId: string): Promise<HumanResolution | null> {
    const payload = await this.request<{ resolution?: HumanResolution | null }>(
      `/review-loop/proposals/${encodeURIComponent(proposalId)}/resolution`,
    );
    return payload.resolution || null;
  }

  async waitForHumanResolution(
    proposalId: string,
    options: ReviewLoopWaitOptions = {},
  ): Promise<HumanResolution | null> {
    const timeoutMs = options.timeoutMs ?? 30_000;
    const pollIntervalMs = options.pollIntervalMs ?? 1_000;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() <= deadline) {
      const resolution = await this.getHumanResolution(proposalId);
      if (resolution) {
        return resolution;
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
    return null;
  }

  resolveReview(input: ResolveReviewInput): Promise<HumanResolution> {
    return this.request("/review-loop/resolutions", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  reportExecution(result: ExecutionResult): Promise<ExecutionResult> {
    return this.request("/review-loop/executions", {
      method: "POST",
      body: JSON.stringify(result),
    });
  }

  reportOutcome(result: OutcomeRecord): Promise<OutcomeRecord> {
    return this.request("/review-loop/outcomes", {
      method: "POST",
      body: JSON.stringify(result),
    });
  }

  exportPreferenceExamples(): Promise<PreferenceExample[]> {
    return this.request("/review-loop/export/preferences");
  }

  exportRewardOutcomeRows(): Promise<RewardOutcomeRow[]> {
    return this.request("/review-loop/export/reward-outcomes");
  }

  exportReplayRows(): Promise<ReplayEventRow[]> {
    return this.request("/review-loop/export/replay");
  }
}

export async function executeReviewedAction<
  TArgs extends ReviewJsonObject,
  TResult,
>(
  options: ExecuteReviewedActionOptions<TArgs, TResult>,
): Promise<ReviewedActionResult<TResult>> {
  const now = options.now || (() => new Date().toISOString());
  const submission = await options.client.submitProposal({
    proposal: normalizeActionProposal(options.proposal, now),
  });
  const waitForResolution = options.waitForResolution ?? false;

  let resolution = submission.human_resolution || null;
  let effectiveArguments = submission.effective_arguments;
  let allowExecution = submission.allow_execution;

  if (!allowExecution && submission.decision.decision === "escalate" && waitForResolution) {
    resolution = await options.client.waitForHumanResolution(
      submission.proposal.proposal_id,
      waitForResolution === true ? undefined : waitForResolution,
    );
    if (resolution) {
      effectiveArguments = applyHumanResolutionArguments(submission.proposal.arguments, resolution);
      allowExecution = resolution.decision !== "reject";
    }
  }

  if (!allowExecution) {
    const executionResult = await options.client.reportExecution({
      proposal_id: submission.proposal.proposal_id,
      executed: false,
      final_arguments: effectiveArguments,
      status: "blocked",
      error: submission.decision.policy_reason || "execution_blocked",
      created_at: now(),
    });
    return {
      submission,
      human_resolution: resolution,
      execution_result: executionResult,
    };
  }

  try {
    const value = await options.execute(effectiveArguments as TArgs);
    const summary = options.summarizeResult?.(value) || {
      status: "succeeded",
      result_summary: summarizeValue(value),
    };
    const executionResult = await options.client.reportExecution({
      proposal_id: submission.proposal.proposal_id,
      executed: true,
      final_arguments: effectiveArguments,
      status: summary.status || "succeeded",
      result_summary: summary.result_summary || null,
      output_reference: summary.output_reference || null,
      metadata: summary.metadata,
      created_at: now(),
    });
    return {
      submission,
      human_resolution: resolution,
      execution_result: executionResult,
      value,
    };
  } catch (error) {
    const executionResult = await options.client.reportExecution({
      proposal_id: submission.proposal.proposal_id,
      executed: true,
      final_arguments: effectiveArguments,
      status: "failed",
      error: error instanceof Error ? error.message : String(error),
      created_at: now(),
    });
    return {
      submission,
      human_resolution: resolution,
      execution_result: executionResult,
    };
  }
}
