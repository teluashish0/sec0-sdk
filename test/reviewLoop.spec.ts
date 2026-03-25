import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FileReviewLoopStore } from "../src/review-loop";
import {
  executeReviewedAction,
  normalizeActionProposal,
} from "../src/review-loop/client";
import type { ReviewLoopClient } from "../src/review-loop/client";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sec0-review-loop-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop()!, { force: true, recursive: true });
  }
});

describe("review-loop store", () => {
  it("exports edited, approved, and rejected preference examples from normalized records", () => {
    const store = new FileReviewLoopStore({ rootDir: makeTempDir() });
    const baseProposal = normalizeActionProposal({
      run_id: "run-1",
      trace_id: "trace-1",
      tenant: "tenant-a",
      domain: "retail",
      agent_id: "agent-1",
      action_type: "tool_call",
      action_name: "modify_pending_order_payment",
      arguments: { order_id: "#1", payment_method_id: "pm_old" },
      observation_context: { explicit_user_confirmation: false },
      metadata: {},
    });

    const approvedProposal = { ...baseProposal, proposal_id: "proposal-approve" };
    const rejectedProposal = { ...baseProposal, proposal_id: "proposal-reject" };
    const editedProposal = { ...baseProposal, proposal_id: "proposal-edit" };

    for (const proposal of [approvedProposal, rejectedProposal, editedProposal]) {
      store.appendProposal(proposal);
      store.appendDecision({
        proposal_id: proposal.proposal_id,
        decision: "escalate",
        findings: [],
        policy_reason: "requires_review",
        created_at: proposal.created_at,
      });
    }

    store.appendResolution({
      proposal_id: approvedProposal.proposal_id,
      decision: "approve",
      reviewer: "alice",
      created_at: approvedProposal.created_at,
    });
    store.appendResolution({
      proposal_id: rejectedProposal.proposal_id,
      decision: "reject",
      reviewer: "alice",
      feedback: "missing consent",
      created_at: rejectedProposal.created_at,
    });
    store.appendResolution({
      proposal_id: editedProposal.proposal_id,
      decision: "edit",
      reviewer: "alice",
      edited_arguments: { order_id: "#1", payment_method_id: "pm_verified" },
      created_at: editedProposal.created_at,
    });

    const examples = store.exportPreferenceExamples();
    expect(examples).toHaveLength(3);
    expect(examples.map((example) => example.preference_kind).sort()).toEqual([
      "approve",
      "edit",
      "reject",
    ]);

    const editedExample = examples.find((example) => example.preference_kind === "edit");
    expect(editedExample?.chosen_completion).toMatchObject({
      mode: "execute",
      arguments: { payment_method_id: "pm_verified" },
    });
    expect(editedExample?.rejected_completion).toMatchObject({
      mode: "execute",
      arguments: { payment_method_id: "pm_old" },
    });
  });
});

describe("executeReviewedAction", () => {
  it("waits for a human edit and reports the edited execution", async () => {
    const submitProposal = vi.fn(async () => ({
      proposal: normalizeActionProposal({
        proposal_id: "proposal-1",
        run_id: "run-1",
        trace_id: "trace-1",
        tenant: "tenant-a",
        domain: "retail",
        agent_id: "agent-1",
        action_type: "tool_call",
        action_name: "modify_pending_order_payment",
        arguments: { payment_method_id: "pm_old" },
        observation_context: {},
        metadata: {},
      }),
      decision: {
        proposal_id: "proposal-1",
        decision: "escalate" as const,
        findings: [],
        policy_reason: "requires_review",
        created_at: new Date().toISOString(),
      },
      human_resolution: null,
      allow_execution: false,
      effective_arguments: { payment_method_id: "pm_old" },
    }));
    const waitForHumanResolution = vi.fn(async () => ({
      resolution_id: "resolution-1",
      proposal_id: "proposal-1",
      decision: "edit" as const,
      reviewer: "alice",
      edited_arguments: { payment_method_id: "pm_verified" },
      created_at: new Date().toISOString(),
    }));
    const reportExecution = vi.fn(async (execution) => execution);

    const client: ReviewLoopClient = {
      submitProposal,
      listPendingReviews: vi.fn(),
      getHumanResolution: vi.fn(),
      waitForHumanResolution,
      resolveReview: vi.fn(),
      reportExecution,
      reportOutcome: vi.fn(),
      exportPreferenceExamples: vi.fn(),
      exportRewardOutcomeRows: vi.fn(),
      exportReplayRows: vi.fn(),
    };

    const execute = vi.fn(async (args: { payment_method_id: string }) => ({
      applied_payment_method_id: args.payment_method_id,
    }));

    const result = await executeReviewedAction({
      client,
      proposal: {
        proposal_id: "proposal-1",
        run_id: "run-1",
        trace_id: "trace-1",
        tenant: "tenant-a",
        domain: "retail",
        agent_id: "agent-1",
        action_type: "tool_call",
        action_name: "modify_pending_order_payment",
        arguments: { payment_method_id: "pm_old" },
        observation_context: {},
        metadata: {},
        created_at: new Date().toISOString(),
      },
      waitForResolution: true,
      execute,
    });

    expect(waitForHumanResolution).toHaveBeenCalledWith("proposal-1", undefined);
    expect(execute).toHaveBeenCalledWith({ payment_method_id: "pm_verified" });
    expect(reportExecution).toHaveBeenCalledWith(
      expect.objectContaining({
        proposal_id: "proposal-1",
        executed: true,
        final_arguments: { payment_method_id: "pm_verified" },
      }),
    );
    expect(result.value).toEqual({ applied_payment_method_id: "pm_verified" });
  });
});
