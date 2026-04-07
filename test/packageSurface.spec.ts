import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

describe("@coreax/sdk package surface", () => {
  const packageDir = path.resolve(__dirname, "..");
  const packageJson = readJson(path.join(packageDir, "package.json"));
  const middlewareIndexPath = path.join(packageDir, "src", "middleware", "index.ts");

  it("publishes the canonical @coreax/sdk export surface", () => {
    expect(packageJson.name).toBe("@coreax/sdk");

    const expectedSubpaths = [
      ".",
      "./policy",
      "./evaluator",
      "./signer",
      "./runtime-adapter",
      "./core",
      "./agent-state",
      "./mandate-ap2",
      "./audit",
      "./otel",
      "./middleware",
      "./escalation",
      "./guard",
      "./governance",
      "./instrumentation",
      "./gateway",
      "./integrations/openclaw",
    ];

    for (const subpath of expectedSubpaths) {
      expect(packageJson.exports).toHaveProperty(subpath);
    }
  });

  it("keeps publish metadata aligned with the canonical package", () => {
    expect(packageJson.private).toBe(false);
    expect(packageJson.name).toBe("@coreax/sdk");
    expect(packageJson.scripts?.prepublishOnly).toBe("npm run publish:guard");
    expect(String(packageJson.description || "")).toContain("Coreax SDK");
  });

  it("keeps middleware/index.ts as a thin public barrel", () => {
    const middlewareIndex = fs.readFileSync(middlewareIndexPath, "utf8");
    const lineCount = middlewareIndex.trim().split("\n").length;

    expect(lineCount).toBeLessThan(140);
    expect(middlewareIndex).toContain('export * from "./securityMiddleware";');
    expect(middlewareIndex).not.toContain("const SDK_VERSION");
    expect(middlewareIndex).not.toContain("export const sec0SecurityMiddleware =");
  });
});
