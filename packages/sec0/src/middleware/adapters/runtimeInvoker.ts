import type { RuntimeInvoker } from "../../core/contracts";
import { createRuntimeAdapter, type RuntimeAdapterConfig } from "../../runtime-adapter";

export function createRuntimeInvoker(config?: RuntimeAdapterConfig): RuntimeInvoker {
  const adapter = createRuntimeAdapter(config);
  return {
    evaluate: (input) => adapter.evaluate(input),
  };
}
