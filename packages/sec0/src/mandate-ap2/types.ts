export type Ap2Config = {
  enabled?: boolean;
  requireForSideEffects?: boolean;
  headers?: { intent?: string; cart?: string; bundle?: string };
  trust?: { didMethods?: string[]; issuersAllowlist?: string[]; clockSkewSec?: number };
  tools?: { allow?: string[] };
  mode?: "" | "observe" | "partial" | "full";
  policyWebhookUrl?: string;
};

export type VerifiedAp2 = {
  ok: boolean;
  reason?: string;
  intentId?: string;
  cartId?: string;
  issuerDid?: string;
  subjectDid?: string;
  constraintsDigest?: string;
  cartDigest?: string;
};

export type NamedCandidate = {
  source: string;
  value: unknown;
};

export type ResolvedValue = {
  value?: string;
  conflict?: string;
};
