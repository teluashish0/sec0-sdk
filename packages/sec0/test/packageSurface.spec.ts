import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

describe("sec0 package surface", () => {
  const packageDir = path.resolve(__dirname, "..");
  const packageJson = readJson(path.join(packageDir, "package.json"));

  it("keeps the canonical OSS sec0 export surface on the workspace package", () => {
    expect(packageJson.name).toBe("sec0");

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

  it("keeps the public repo rooted at a single sec0 workspace package", () => {
    const repoRoot = path.resolve(packageDir, "..", "..");
    const rootPackageJson = readJson(path.join(repoRoot, "package.json"));
    const packageDirs = fs.readdirSync(path.join(repoRoot, "packages"), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();

    expect(rootPackageJson.private).toBe(true);
    expect(rootPackageJson.workspaces).toEqual(["packages/*"]);
    expect(packageDirs).toEqual(["sec0"]);
    expect(fs.existsSync(path.join(repoRoot, "src"))).toBe(false);
    expect(fs.existsSync(path.join(repoRoot, "apps"))).toBe(false);
  });
});
