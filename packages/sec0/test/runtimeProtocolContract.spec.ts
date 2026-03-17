import { describe, expect, it } from "vitest";
import { RUNTIME_PROTOCOL_VERSION } from "../src/runtime-adapter";

describe("runtime protocol contract", () => {
  it("keeps the public SDK runtime protocol version self-contained and date-versioned", () => {
    expect(RUNTIME_PROTOCOL_VERSION).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});
