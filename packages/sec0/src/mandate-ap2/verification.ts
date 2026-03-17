import type { Ap2Config, VerifiedAp2, NamedCandidate } from "./types";
import { LOG_PREFIX } from "./constants";
import { logger } from "./logger";
import { safeJsonParse } from "./encoding";
import { canonicalizeJson, sha256Hex, computeArgsDigest } from "./digest";
import { decodeMandatePayload } from "./mandate";
import {
  getHeader,
  requireHeaderName,
  collectBundleCandidates,
  resolveUniqueString,
  normalizeAllowedDidMethods,
} from "./headers";
import { didResolver } from "./did";

/**
 * Verify AP2 intent and cart mandates from request headers.
 * Returns a VerifiedAp2 result with derived identifiers and digests.
 */
export async function verifyAp2MandatesFromHeaders(
  cfg: Ap2Config | undefined,
  headers: Record<string, string | string[] | undefined>,
  effectiveArgs: unknown
): Promise<VerifiedAp2> {
  try {
    if (!cfg?.headers) {
      throw new Error(`${LOG_PREFIX} cfg.headers must provide intent, cart, and bundle names`);
    }

    const intentHdr = requireHeaderName(cfg.headers.intent, "ap2.headers.intent");
    const cartHdr = requireHeaderName(cfg.headers.cart, "ap2.headers.cart");
    const bundleHdr = requireHeaderName(cfg.headers.bundle, "ap2.headers.bundle");

    const intentHeaderValue = getHeader(headers, intentHdr);
    const cartHeaderValue = getHeader(headers, cartHdr);
    const bundleRaw = getHeader(headers, bundleHdr);
    const bundleObj = safeJsonParse(bundleRaw);

    const bundleIntentSources = collectBundleCandidates(bundleObj, [
      { source: "bundle.intent", key: "intent" },
      { source: "bundle.intentMandate", key: "intentMandate" },
    ]);
    const bundleCartSources = collectBundleCandidates(bundleObj, [
      { source: "bundle.cart", key: "cart" },
      { source: "bundle.cartMandate", key: "cartMandate" },
    ]);

    const intentSources: NamedCandidate[] = [
      { source: "header.intent", value: intentHeaderValue },
      ...bundleIntentSources,
    ];
    const cartSources: NamedCandidate[] = [
      { source: "header.cart", value: cartHeaderValue },
      ...bundleCartSources,
    ];

    const { value: intentRaw, conflict: intentMandateConflict } =
      resolveUniqueString("intent_mandate", intentSources);
    const { value: cartRaw, conflict: cartMandateConflict } =
      resolveUniqueString("cart_mandate", cartSources);

    if (intentMandateConflict) return { ok: false, reason: "ap2_intent_mandate_conflict" };
    if (cartMandateConflict) return { ok: false, reason: "ap2_cart_mandate_conflict" };
    if (!intentRaw) return { ok: false, reason: "ap2_intent_missing" };
    if (!cartRaw) return { ok: false, reason: "ap2_mandate_missing" };

    const allowedMethods = normalizeAllowedDidMethods(cfg.trust);

    const intentPayload = decodeMandatePayload(intentRaw) as Record<string, unknown> | undefined;
    const cartPayload = decodeMandatePayload(cartRaw) as Record<string, unknown> | undefined;

    const constraintsDigest = intentPayload?.constraints
      ? sha256Hex(Buffer.from(canonicalizeJson(intentPayload.constraints)))
      : undefined;
    const cartDigest = cartPayload
      ? sha256Hex(Buffer.from(canonicalizeJson(cartPayload)))
      : undefined;

    const { value: intentId, conflict: intentConflict } = resolveUniqueString("intent_id", [
      { source: "intent_payload.jti", value: intentPayload?.jti },
      { source: "intent_payload.id", value: intentPayload?.id },
    ]);
    const { value: cartId, conflict: cartConflict } = resolveUniqueString("cart_id", [
      { source: "cart_payload.jti", value: cartPayload?.jti },
      { source: "cart_payload.id", value: cartPayload?.id },
    ]);
    const { value: issuerDid, conflict: issuerConflict } = resolveUniqueString("issuer_did", [
      { source: "cart_payload.iss", value: cartPayload?.iss },
      { source: "cart_payload.issuer", value: cartPayload?.issuer },
    ]);
    const { value: subjectDid, conflict: subjectConflict } = resolveUniqueString("subject_did", [
      { source: "cart_payload.sub", value: cartPayload?.sub },
      { source: "cart_payload.subject", value: cartPayload?.subject },
    ]);

    let reason: string | undefined = undefined;

    if (cartPayload?.args) {
      try {
        const left = sha256Hex(Buffer.from(canonicalizeJson(cartPayload.args)));
        const right = computeArgsDigest(effectiveArgs);
        if (left !== right) reason = "ap2_cart_mismatch";
      } catch (err) {
        logger.warn("Cart args comparison failed", { error: (err as Error)?.message });
      }
    }

    if (!reason) {
      if (intentConflict) reason = "ap2_intent_id_conflict";
      else if (cartConflict) reason = "ap2_cart_id_conflict";
      else if (issuerConflict) reason = "ap2_issuer_conflict";
      else if (subjectConflict) reason = "ap2_subject_conflict";
    }

    if (!reason && issuerDid) {
      void didResolver.resolve(issuerDid);
      const method = issuerDid.split(":")[1]?.toLowerCase();
      if (method && allowedMethods.length && !allowedMethods.includes(`did:${method}`)) {
        reason = "ap2_vc_untrusted";
      }
      if (!reason && cfg.trust?.issuersAllowlist) {
        const allowed = cfg.trust.issuersAllowlist.some(
          (x) => String(x).toLowerCase() === issuerDid.toLowerCase()
        );
        if (!allowed) reason = "ap2_vc_untrusted";
      }
    }

    return {
      ok: !reason,
      reason,
      intentId,
      cartId,
      issuerDid,
      subjectDid,
      constraintsDigest,
      cartDigest,
    };
  } catch (err) {
    logger.error("AP2 mandate verification failed", { error: (err as Error)?.message });
    return { ok: false, reason: "ap2_verification_error" };
  }
}
