import { Sec0Appender, type Sec0Config } from "../../audit";
import type { AuditSink } from "../../core/contracts";
import type { Signer } from "../../signer";

/**
 * @deprecated Use createCoreaxAuditSink for new integrations.
 */
export function createSec0AuditSink(opts: { config: Sec0Config; signer: Signer }): AuditSink {
  const appender = new Sec0Appender(opts);
  return {
    append(envelope) {
      return appender.append(envelope);
    },
    appendRawPayload(event) {
      return appender.appendRawPayload(event);
    },
    flush() {
      return appender.flush();
    },
  };
}

export const createCoreaxAuditSink = createSec0AuditSink;
