import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function existingPaths(paths: string[]): string[] {
  return paths.filter((filePath) => fs.existsSync(filePath));
}

describe("sec0-sdk package surface", () => {
  const packageDir = path.resolve(__dirname, "..");
  const packageJson = readJson(path.join(packageDir, "package.json"));
  const middlewareIndexPath = path.join(packageDir, "src", "middleware", "index.ts");

  it("keeps the legacy standalone export surface on the workspace package", () => {
    expect(packageJson.name).toBe("sec0-sdk-legacy");

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
      "./instrumentation",
      "./gateway",
      "./integrations/openclaw",
    ];

    for (const subpath of expectedSubpaths) {
      expect(packageJson.exports).toHaveProperty(subpath);
    }
  });

  it("prevents legacy standalone copies from reclaiming canonical package identities", () => {
    const repoRoot = path.resolve(packageDir, "..", "..");
    const workspaceRoot = path.resolve(repoRoot, "..");
    const legacyPackages = [
      {
        paths: existingPaths([
          path.join(repoRoot, "sec0-sdk", "package.json"),
          path.join(workspaceRoot, "sec0-sdk", "package.json"),
        ]),
        canonicalName: "sec0-sdk",
      },
      {
        paths: existingPaths([
          path.join(repoRoot, "sec0-client-sdk", "package.json"),
          path.join(workspaceRoot, "sec0-client-sdk", "package.json"),
        ]),
        canonicalName: "@sec0/client-sdk",
      },
      {
        paths: existingPaths([
          path.join(repoRoot, "sec0-runtime-protocol", "package.json"),
          path.join(workspaceRoot, "sec0-runtime-protocol", "package.json"),
        ]),
        canonicalName: "sec0-runtime-protocol",
      },
    ];

    for (const legacyPackage of legacyPackages) {
      for (const legacyPath of legacyPackage.paths) {
        const legacyManifest = readJson(legacyPath);
        expect(legacyManifest.private).toBe(true);
        expect(legacyManifest.name).not.toBe(legacyPackage.canonicalName);
      }
    }
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
