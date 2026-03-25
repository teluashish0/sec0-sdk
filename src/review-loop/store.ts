import { createHash, randomUUID } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import type {
  ActionProposal,
  ExecutionResult,
  HumanResolution,
  OutcomeRecord,
  PendingReview,
  PreferenceComparison,
  PreferenceExample,
  ReplayEventRow,
  RewardOutcomeRow,
  ReviewJsonObject,
  ReviewJsonValue,
  ReviewLoopRecord,
  Sec0Decision,
} from "./types";

export interface FileReviewLoopStorePaths {
  proposals: string;
  decisions: string;
  resolutions: string;
  executions: string;
  outcomes: string;
}

export interface FileReviewLoopStoreConfig {
  rootDir: string;
  paths?: Partial<FileReviewLoopStorePaths>;
}

function defaultPaths(rootDir: string): FileReviewLoopStorePaths {
  return {
    proposals: resolve(rootDir, "action-proposals.ndjson"),
    decisions: resolve(rootDir, "sec0-decisions.ndjson"),
    resolutions: resolve(rootDir, "human-resolutions.ndjson"),
    executions: resolve(rootDir, "execution-results.ndjson"),
    outcomes: resolve(rootDir, "outcome-records.ndjson"),
  };
}

function ensureParent(filePath: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
}

function appendNdjson(filePath: string, row: unknown): void {
  ensureParent(filePath);
  appendFileSync(filePath, `${JSON.stringify(row)}\n`, "utf8");
}

function readNdjson<T>(filePath: string): T[] {
  if (!existsSync(filePath)) {
    return [];
  }
  return readFileSync(filePath, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as T);
}

function stableJson(value: ReviewJsonValue | undefined): ReviewJsonValue {
  if (Array.isArray(value)) {
    return value.map((item) => stableJson(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nestedValue]) => [key, stableJson(nestedValue)]),
    );
  }
  return value ?? null;
}

function stringifyStable(value: ReviewJsonValue | undefined): string {
  return JSON.stringify(stableJson(value));
}

function hashValue(value: ReviewJsonValue | undefined): string {
  return createHash("sha256").update(stringifyStable(value)).digest("hex");
}

function proposalPrompt(proposal: ActionProposal): string {
  return [
    `tenant: ${proposal.tenant}`,
    `domain: ${proposal.domain}`,
    `agent_id: ${proposal.agent_id}`,
    `run_id: ${proposal.run_id}`,
    `action_type: ${proposal.action_type}`,
    `action_name: ${proposal.action_name}`,
    `arguments: ${stringifyStable(proposal.arguments)}`,
    `observation_context: ${stringifyStable(proposal.observation_context)}`,
    `metadata: ${stringifyStable(proposal.metadata)}`,
  ].join("\n");
}

function assistantCompletion(payload: ReviewJsonObject): PreferenceComparison["completion_A"] {
  return [{ role: "assistant", content: JSON.stringify(payload) }];
}

function chosenAndRejectedForResolution(
  proposal: ActionProposal,
  resolution: HumanResolution,
): {
  chosen: ReviewJsonObject;
  rejected: ReviewJsonObject;
} {
  const executeOriginal: ReviewJsonObject = {
    mode: "execute",
    action_type: proposal.action_type,
    action_name: proposal.action_name,
    arguments: stableJson(proposal.arguments) as ReviewJsonObject,
  };
  if (resolution.decision === "edit") {
    return {
      chosen: {
        mode: "execute",
        action_type: proposal.action_type,
        action_name: proposal.action_name,
        arguments: stableJson(resolution.edited_arguments || {}) as ReviewJsonObject,
      },
      rejected: executeOriginal,
    };
  }
  if (resolution.decision === "reject") {
    return {
      chosen: {
        mode: "reject",
        action_type: proposal.action_type,
        action_name: proposal.action_name,
        reason: resolution.feedback || "human_rejected",
      },
      rejected: executeOriginal,
    };
  }
  return {
    chosen: executeOriginal,
    rejected: {
      mode: "escalate",
      action_type: proposal.action_type,
      action_name: proposal.action_name,
      reason: "unnecessary_review_loop",
    },
  };
}

function latestByProposalId<T extends { proposal_id: string }>(rows: T[]): Map<string, T> {
  const out = new Map<string, T>();
  for (const row of rows) {
    out.set(row.proposal_id, row);
  }
  return out;
}

function latestOutcomeByProposalId(rows: OutcomeRecord[]): Map<string, OutcomeRecord> {
  const out = new Map<string, OutcomeRecord>();
  for (const row of rows) {
    if (row.proposal_id) {
      out.set(row.proposal_id, row);
    }
  }
  return out;
}

function replayPayload(row: unknown): ReviewJsonObject {
  return JSON.parse(JSON.stringify(row)) as ReviewJsonObject;
}

export class FileReviewLoopStore {
  readonly paths: FileReviewLoopStorePaths;

  constructor(config: FileReviewLoopStoreConfig) {
    this.paths = {
      ...defaultPaths(config.rootDir),
      ...(config.paths || {}),
    };
  }

  appendProposal(proposal: ActionProposal): ActionProposal {
    appendNdjson(this.paths.proposals, proposal);
    return proposal;
  }

  appendDecision(decision: Sec0Decision): Sec0Decision {
    appendNdjson(this.paths.decisions, decision);
    return decision;
  }

  appendResolution(
    resolution: Omit<HumanResolution, "resolution_id"> & { resolution_id?: string },
  ): HumanResolution {
    const normalized: HumanResolution = {
      ...resolution,
      resolution_id: resolution.resolution_id || randomUUID(),
    };
    appendNdjson(this.paths.resolutions, normalized);
    return normalized;
  }

  appendExecution(result: ExecutionResult): ExecutionResult {
    appendNdjson(this.paths.executions, result);
    return result;
  }

  appendOutcome(
    outcome: OutcomeRecord,
  ): OutcomeRecord {
    const normalized: OutcomeRecord = {
      ...outcome,
      outcome_id: outcome.outcome_id || randomUUID(),
    };
    appendNdjson(this.paths.outcomes, normalized);
    return normalized;
  }

  readProposals(): ActionProposal[] {
    return readNdjson<ActionProposal>(this.paths.proposals);
  }

  readDecisions(): Sec0Decision[] {
    return readNdjson<Sec0Decision>(this.paths.decisions);
  }

  readResolutions(): HumanResolution[] {
    return readNdjson<HumanResolution>(this.paths.resolutions);
  }

  readExecutions(): ExecutionResult[] {
    return readNdjson<ExecutionResult>(this.paths.executions);
  }

  readOutcomes(): OutcomeRecord[] {
    return readNdjson<OutcomeRecord>(this.paths.outcomes);
  }

  getProposal(proposalId: string): ActionProposal | null {
    return this.readProposals().find((proposal) => proposal.proposal_id === proposalId) || null;
  }

  getDecision(proposalId: string): Sec0Decision | null {
    return this.readDecisions().find((decision) => decision.proposal_id === proposalId) || null;
  }

  getLatestResolution(proposalId: string): HumanResolution | null {
    const matches = this.readResolutions().filter((resolution) => resolution.proposal_id === proposalId);
    return matches.at(-1) || null;
  }

  getLatestResolutionByReviewId(reviewId: string): HumanResolution | null {
    const matches = this.readResolutions().filter(
      (resolution) => String(resolution.metadata?.review_id || "") === reviewId,
    );
    return matches.at(-1) || null;
  }

  listPendingReviews(): PendingReview[] {
    const proposals = latestByProposalId(this.readProposals());
    const decisions = latestByProposalId(this.readDecisions());
    const resolutions = latestByProposalId(this.readResolutions());

    return [...decisions.values()]
      .filter((decision) => decision.decision === "escalate")
      .filter((decision) => !resolutions.has(decision.proposal_id))
      .map((decision) => ({
        proposal: proposals.get(decision.proposal_id)!,
        decision,
        latest_resolution: null,
      }))
      .filter((pending) => Boolean(pending.proposal));
  }

  getReviewKey(proposal: ActionProposal): string {
    const explicitKey = proposal.metadata?.review_key;
    if (typeof explicitKey === "string" && explicitKey.trim()) {
      return explicitKey;
    }
    return hashValue({
      tenant: proposal.tenant,
      domain: proposal.domain,
      action_type: proposal.action_type,
      action_name: proposal.action_name,
      arguments: proposal.arguments,
    });
  }

  getLatestResolutionForEquivalentProposal(proposal: ActionProposal): HumanResolution | null {
    const reviewKey = this.getReviewKey(proposal);
    const proposalsById = latestByProposalId(this.readProposals());
    const resolutions = this.readResolutions();
    const matches = resolutions.filter((resolution) => {
      const candidateProposal = proposalsById.get(resolution.proposal_id);
      return Boolean(candidateProposal) && this.getReviewKey(candidateProposal!) === reviewKey;
    });
    return matches.at(-1) || null;
  }

  getJoinedRecords(): ReviewLoopRecord[] {
    const proposals = this.readProposals();
    const decisions = latestByProposalId(this.readDecisions());
    const resolutions = latestByProposalId(this.readResolutions());
    const executions = latestByProposalId(this.readExecutions());
    const outcomes = latestOutcomeByProposalId(this.readOutcomes());

    return proposals.map((proposal) => ({
      proposal,
      decision: decisions.get(proposal.proposal_id),
      human_resolution: resolutions.get(proposal.proposal_id) || null,
      execution_result: executions.get(proposal.proposal_id) || null,
      outcome_record: outcomes.get(proposal.proposal_id) || null,
    }));
  }

  exportPreferenceExamples(): PreferenceExample[] {
    return this.getJoinedRecords()
      .filter((record) => Boolean(record.human_resolution))
      .map((record) => {
        const resolution = record.human_resolution!;
        const { chosen, rejected } = chosenAndRejectedForResolution(record.proposal, resolution);
        return {
          proposal_id: record.proposal.proposal_id,
          resolution_id: resolution.resolution_id,
          preference_kind: resolution.decision,
          comparison: {
            prompt_conversation: [
              {
                role: "system",
                content:
                  "Choose the preferred next action for this governance-sensitive agent action.",
              },
              {
                role: "user",
                content: proposalPrompt(record.proposal),
              },
            ],
            completion_A: assistantCompletion(chosen),
            completion_B: assistantCompletion(rejected),
          },
          label: "A",
          chosen_completion: chosen,
          rejected_completion: rejected,
          metadata: {
            review_key: this.getReviewKey(record.proposal),
            proposal_argument_hash: hashValue(record.proposal.arguments),
            resolution_feedback: resolution.feedback || null,
          },
        };
      });
  }

  exportRewardOutcomeRows(): RewardOutcomeRow[] {
    return this.getJoinedRecords().map((record) => ({
      ...record,
      proposal_id: record.proposal.proposal_id,
      run_id: record.proposal.run_id,
    }));
  }

  exportReplayRows(): ReplayEventRow[] {
    const proposals = this.readProposals().map((proposal) => ({
      proposal_id: proposal.proposal_id,
      run_id: proposal.run_id,
      event_type: "action_proposal" as const,
      created_at: proposal.created_at,
      payload: replayPayload(proposal),
    }));
    const decisions = this.readDecisions().map((decision) => ({
      proposal_id: decision.proposal_id,
      run_id: this.getProposal(decision.proposal_id)?.run_id || null,
      event_type: "sec0_decision" as const,
      created_at: decision.created_at,
      payload: replayPayload(decision),
    }));
    const resolutions = this.readResolutions().map((resolution) => ({
      proposal_id: resolution.proposal_id,
      run_id: this.getProposal(resolution.proposal_id)?.run_id || null,
      event_type: "human_resolution" as const,
      created_at: resolution.created_at,
      payload: replayPayload(resolution),
    }));
    const executions = this.readExecutions().map((execution) => ({
      proposal_id: execution.proposal_id,
      run_id: this.getProposal(execution.proposal_id)?.run_id || null,
      event_type: "execution_result" as const,
      created_at: execution.created_at,
      payload: replayPayload(execution),
    }));
    const outcomes = this.readOutcomes().map((outcome) => ({
      proposal_id: outcome.proposal_id || "",
      run_id: outcome.run_id || this.getProposal(String(outcome.proposal_id || ""))?.run_id || null,
      event_type: "outcome_record" as const,
      created_at: outcome.created_at,
      payload: replayPayload(outcome),
    }));

    return [...proposals, ...decisions, ...resolutions, ...executions, ...outcomes]
      .filter((row) => row.proposal_id.length > 0)
      .sort((left, right) => left.created_at.localeCompare(right.created_at));
  }
}
