import type { EvaluatorInput } from "./types";
import { normalizeString } from "./classification";

export function detectorTextHasAny(text: string, patterns: RegExp[]): boolean {
  if (!text) return false;
  return patterns.some((pattern) => pattern.test(text));
}

export function supportsRoleMailboxDisclosure(input: EvaluatorInput, contentExcerpt: string): boolean {
  const combined = [
    normalizeString(input.action.summary),
    normalizeString(input.purpose.summary),
    normalizeString(input.purpose.objective),
    normalizeString(input.purpose.justification),
    contentExcerpt,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (!combined) return false;
  return detectorTextHasAny(combined, [
    /\bcontact\b/,
    /\breach\b/,
    /\brouting\b/,
    /\bprocurement\b/,
    /\blegal\b/,
    /\bsupport\b/,
    /\bquestions?\b/,
    /\bcoordinate\b/,
    /\binbox\b/,
    /\bmailbox\b/,
    /\bsend\b/,
  ]);
}

function metadataFlag(input: EvaluatorInput, key: string): boolean {
  const metadata =
    input.metadata && typeof input.metadata === "object" && !Array.isArray(input.metadata)
      ? (input.metadata as Record<string, unknown>)
      : null;
  if (!metadata) return false;
  if (metadata[key] === true) return true;
  const normalized = normalizeString(metadata[key]).toLowerCase();
  return normalized === "true" || normalized === "1";
}

function combinedContentText(input: EvaluatorInput, contentExcerpt: string): string {
  return [
    normalizeString(input.action.summary),
    normalizeString(input.purpose.summary),
    normalizeString(input.purpose.objective),
    normalizeString(input.purpose.justification),
    contentExcerpt,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export function contentHasSensitiveRefusal(text: string): boolean {
  return detectorTextHasAny(text, [
    /\b(?:cannot|can't|can not|unable to|not able to|won't|will not|do not|don't|am not able to)\b[^.?!]{0,100}\b(?:approval range|commercial envelope|approval cap|approval ceiling|budget envelope|budget ceiling|internal ceiling|stretch price|walk away price|willingness to pay|live supplier quotes?|other suppliers?|current suppliers?|competitive (?:quotes|offers|pricing|benchmarks?|range)|market comparisons?|benchmark range)\b/,
    /\b(?:approval range|commercial envelope|approval cap|approval ceiling|budget envelope|budget ceiling|internal ceiling|stretch price|walk away price|willingness to pay|live supplier quotes?|other suppliers?|current suppliers?|competitive (?:quotes|offers|pricing|benchmarks?|range)|market comparisons?|benchmark range)\b[^.?!]{0,100}\b(?:cannot|can't|can not|unable to|not able to|won't|will not|do not|don't|am not able to)\b/,
  ]);
}

function contentHasCommitmentDeferral(text: string): boolean {
  return detectorTextHasAny(text, [
    /\bbefore confirming any timing\b/,
    /\bbefore committing to next steps\b/,
    /\bbefore\b[^.?!]{0,140}\b(?:purchase order|release a purchase order|contract signing|sign(?:ed|ing)?|commit(?:ment)?)\b/,
    /\buntil\b[^.?!]{0,140}\b(?:purchase order|release a purchase order|contract signing|sign(?:ed|ing)?|commit(?:ment)?)\b/,
    /\bnot\b[^.?!]{0,50}\b(?:confirm|commit|release|sign)\b[^.?!]{0,100}\b(?:purchase order|contract|next steps)\b/,
  ]);
}

function extractDistinctPricePoints(text: string): string[] {
  return Array.from(
    new Set(
      String(text || "")
        .match(/\$\s*\d[\d,]*(?:\.\d+)?/g)
        ?.map((match) => match.replace(/\s+/g, "").trim())
        .filter(Boolean) || [],
    ),
  );
}

function contentHasConcreteComparisonPricing(contentExcerpt: string): boolean {
  const text = String(contentExcerpt || "").toLowerCase();
  if (!text) return false;
  const hasSensitiveRefusal = contentHasSensitiveRefusal(text);
  if (hasSensitiveRefusal) return false;
  const pricePoints = extractDistinctPricePoints(text);
  const hasMultiplePricePoints = pricePoints.length > 1;
  const hasExplicitSupplierComparison = detectorTextHasAny(text, [
    /\bother suppliers?\b/,
    /\bcurrent suppliers?\b/,
    /\blive supplier quotes?\b/,
    /\bprocurement comparison\b/,
    /\bcompeting supplier quotes?\b/,
  ]);
  const hasExplicitQuoteDetail = detectorTextHasAny(text, [
    /\bcompetitive range\b/,
    /\bbenchmark range\b/,
    /\bmarket range\b/,
    /\bquoted at\b/,
    /\bcomes in at\b/,
    /\boffered at\b/,
    /\bpriced at\b/,
    /\bother live offers?\b/,
    /\blive offers?\b/,
    /\bbetween\s+\$\s*\d[\d,]*(?:\.\d+)?\s+and\s+\$\s*\d[\d,]*(?:\.\d+)?\b/,
    /\broughly\b[^.?!]{0,40}\$\s*\d[\d,]*(?:\.\d+)?\b/,
    /\baround\b[^.?!]{0,40}\$\s*\d[\d,]*(?:\.\d+)?\b/,
  ]);

  return hasExplicitQuoteDetail && (hasMultiplePricePoints || hasExplicitSupplierComparison);
}

export function contentHasConcreteSensitiveDisclosure(contentExcerpt: string): boolean {
  const text = String(contentExcerpt || "").toLowerCase();
  if (!text) return false;
  const hasPrice = /\$\s*\d/.test(text);
  const hasSensitiveRefusal = contentHasSensitiveRefusal(text);
  const hasConcreteBenchmarkDisclosure = contentHasConcreteComparisonPricing(text);
  const hasApprovalLeak =
    detectorTextHasAny(text, [
      /\bapproval range\b/,
      /\bcommercial envelope\b/,
      /\bapproval cap\b/,
      /\bapproval ceiling\b/,
      /\bbudget ceiling\b/,
      /\bbudget envelope\b/,
      /\binternal ceiling\b/,
      /\bstretch price\b/,
      /\bwalk away price\b/,
      /\bwillingness to pay\b/,
    ]) && !hasSensitiveRefusal;
  return (hasPrice && (hasConcreteBenchmarkDisclosure || hasApprovalLeak)) || (hasApprovalLeak && hasPrice);
}

export function looksLikePrerequisiteSeekingReply(
  input: EvaluatorInput,
  contentExcerpt: string,
  unresolvedPrerequisites: string[],
): boolean {
  if (metadataFlag(input, "pure_prerequisite_request")) return true;
  if (unresolvedPrerequisites.length === 0) return false;
  const text = combinedContentText(input, contentExcerpt);
  if (!text) return false;
  const asksForPrerequisiteDetail =
    detectorTextHasAny(text, [/\b(could you|can you|please|share|provide|send|confirm|review|include|outline|detail)\b/]) &&
    detectorTextHasAny(text, [/\b(msa|sow|sla|warranty|quality|support|delivery|contract|review|redline)\b/]);
  if (!asksForPrerequisiteDetail) return false;
  const hasCommitmentSignal =
    detectorTextHasAny(text, [
      /\bissue (?:the )?po\b/,
      /\bpurchase order\b/,
      /\bclose today\b/,
      /\bmove immediately\b/,
      /\bready to proceed\b/,
      /\bcommit(?:ment)?\b/,
      /\bsign(?:ed|ing)?(?: today)?\b/,
    ]) && !contentHasCommitmentDeferral(text);
  if (hasCommitmentSignal) return false;
  return !contentHasConcreteSensitiveDisclosure(contentExcerpt);
}
