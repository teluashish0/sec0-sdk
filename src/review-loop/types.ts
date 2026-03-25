export type ReviewJsonPrimitive = string | number | boolean | null;
export type ReviewJsonValue =
  | ReviewJsonPrimitive
  | ReviewJsonValue[]
  | { [key: string]: ReviewJsonValue };

export interface ReviewJsonObject {
  [key: string]: ReviewJsonValue;
}

export type ReviewMessageRole = "system" | "user" | "assistant";

export interface ReviewMessage {
  role: ReviewMessageRole;
  content: string;
}

export interface ReviewFinding {
  code: string;
  message: string;
  severity?: "low" | "medium" | "high" | "critical" | string;
  source?: string;
  metadata?: ReviewJsonObject;
}

export interface ActionProposal {
  proposal_id: string;
  run_id: string;
  trace_id?: string | null;
  tenant: string;
  domain: string;
  agent_id: string;
  action_type: string;
  action_name: string;
  arguments: ReviewJsonObject;
  observation_context: ReviewJsonObject;
  metadata: ReviewJsonObject;
  created_at: string;
}

export type Sec0DecisionValue = "allow" | "deny" | "escalate";

export interface Sec0Decision {
  proposal_id: string;
  decision: Sec0DecisionValue;
  findings: ReviewFinding[];
  policy_reason?: string | null;
  risk_labels?: string[];
  observe_only?: boolean;
  metadata?: ReviewJsonObject;
  created_at: string;
}

export type HumanResolutionDecision = "approve" | "reject" | "edit";

export interface HumanResolution {
  resolution_id: string;
  proposal_id: string;
  decision: HumanResolutionDecision;
  reviewer: string;
  feedback?: string | null;
  edited_arguments?: ReviewJsonObject | null;
  metadata?: ReviewJsonObject;
  created_at: string;
}

export interface ExecutionResult {
  proposal_id: string;
  executed: boolean;
  final_arguments?: ReviewJsonObject | null;
  status: string;
  result_summary?: string | null;
  output_reference?: string | null;
  error?: string | null;
  metadata?: ReviewJsonObject;
  created_at: string;
}

export interface VerifierResult {
  passed?: boolean | null;
  score?: number | null;
  status?: string | null;
  details?: ReviewJsonObject;
}

export interface OutcomeRecord {
  outcome_id?: string;
  proposal_id?: string | null;
  run_id?: string | null;
  task_success?: boolean | null;
  outcome_success?: boolean | null;
  verifier_result?: VerifierResult | null;
  reward_components?: Record<string, number>;
  business_outcome?: ReviewJsonObject;
  metadata?: ReviewJsonObject;
  created_at: string;
}

export interface ReviewSubmission {
  proposal: ActionProposal;
  decision: Sec0Decision;
  human_resolution?: HumanResolution | null;
  allow_execution: boolean;
  effective_arguments: ReviewJsonObject;
  audit?: ReviewJsonObject;
  guard?: ReviewJsonObject;
  metadata?: ReviewJsonObject;
}

export interface PendingReview {
  proposal: ActionProposal;
  decision: Sec0Decision;
  latest_resolution?: HumanResolution | null;
}

export interface ReviewLoopRecord {
  proposal: ActionProposal;
  decision?: Sec0Decision;
  human_resolution?: HumanResolution | null;
  execution_result?: ExecutionResult | null;
  outcome_record?: OutcomeRecord | null;
}

export interface PreferenceComparison {
  prompt_conversation: ReviewMessage[];
  completion_A: ReviewMessage[];
  completion_B: ReviewMessage[];
}

export interface PreferenceExample {
  proposal_id: string;
  resolution_id: string;
  preference_kind: HumanResolutionDecision;
  comparison: PreferenceComparison;
  label: "A" | "B" | "Tie";
  chosen_completion: ReviewJsonObject;
  rejected_completion: ReviewJsonObject;
  metadata?: ReviewJsonObject;
}

export interface RewardOutcomeRow extends ReviewLoopRecord {
  proposal_id: string;
  run_id: string;
}

export interface ReplayEventRow {
  proposal_id: string;
  run_id?: string | null;
  event_type:
    | "action_proposal"
    | "sec0_decision"
    | "human_resolution"
    | "execution_result"
    | "outcome_record";
  created_at: string;
  payload: ReviewJsonObject;
}

export interface ReviewLoopWaitOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
}

export interface ResolveReviewInput {
  proposal_id?: string;
  review_id?: string;
  decision: HumanResolutionDecision;
  reviewer: string;
  feedback?: string | null;
  edited_arguments?: ReviewJsonObject | null;
  metadata?: ReviewJsonObject;
}
