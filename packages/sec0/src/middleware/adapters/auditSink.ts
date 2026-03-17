import { Sec0Appender, type Sec0Config } from "../../audit";
import type { AuditSink } from "../../core/contracts";
import type { Signer } from "../../signer";

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
