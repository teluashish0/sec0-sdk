import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { RUNTIME_PROTOCOL_VERSION } from "../src/runtime-adapter";

function resolveProtocolSpecPath(): string | null {
  const envSpecifiedPath = process.env.SEC0_RUNTIME_PROTOCOL_SPEC?.trim();
  const candidates = [
    envSpecifiedPath || "",
    path.resolve(__dirname, "..", "..", "..", ".deps", "sec0-runtime-protocol", "openapi", "runtime-enforcement.yaml"),
    path.resolve(__dirname, "..", "..", "..", "sec0-runtime-protocol", "openapi", "runtime-enforcement.yaml"),
    path.resolve(__dirname, "..", "..", "sec0-runtime-protocol", "openapi", "runtime-enforcement.yaml"),
    path.resolve(__dirname, "..", "..", "..", "..", "sec0-runtime-protocol", "openapi", "runtime-enforcement.yaml"),
    path.resolve(__dirname, "..", "..", "packages", "sec0-runtime-protocol", "openapi", "runtime-enforcement.yaml"),
  ];
  return candidates.find((candidate) => candidate && fs.existsSync(candidate)) ?? null;
}

function readProtocolSpecVersion(specPath: string): string {
  const source = fs.readFileSync(specPath, "utf8");
  const match = source.match(/^\s*version:\s*([0-9-]+)\s*$/m);
  if (!match?.[1]) {
    throw new Error(`Unable to locate protocol version in ${specPath}`);
  }
  return match[1];
}

describe("runtime protocol contract", () => {
  const specPath = resolveProtocolSpecPath();

  it("publishes a date-stamped runtime protocol version", () => {
    expect(RUNTIME_PROTOCOL_VERSION).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  (specPath ? it : it.skip)("keeps the public SDK runtime version aligned with sec0-runtime-protocol", () => {
    expect(RUNTIME_PROTOCOL_VERSION).toBe(readProtocolSpecVersion(specPath!));
  });
});
