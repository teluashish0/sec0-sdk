import { describe, expect, it } from "vitest";
import { SkillScanManager } from "../src/middleware/skill";

describe("SkillScanManager", () => {
  it("raises skill_scan_failed when a failed scan meets the configured threshold", () => {
    const manager = new SkillScanManager();

    const result = manager.shouldBlock(
      {
        status: "fail",
        updatedAt: Date.now(),
        findings: [
          {
            code: "SKILL-1",
            title: "Risky skill finding",
            severity: "low",
            message: "A finding was reported.",
          },
        ],
      },
      "low",
    );

    expect(result).toMatchObject({
      block: true,
      reason: "skill_scan_failed",
      maxSeverity: "low",
    });
  });

  it("does not raise skill_scan_failed when findings are below the configured threshold", () => {
    const manager = new SkillScanManager();

    const result = manager.shouldBlock(
      {
        status: "fail",
        updatedAt: Date.now(),
        findings: [
          {
            code: "SKILL-1",
            title: "Risky skill finding",
            severity: "low",
            message: "A finding was reported.",
          },
        ],
      },
      "high",
    );

    expect(result).toMatchObject({ block: false });
  });

  it("does not block pending scans", () => {
    const manager = new SkillScanManager();

    const result = manager.shouldBlock(
      {
        status: "pending",
        updatedAt: Date.now(),
      },
      "low",
    );

    expect(result).toMatchObject({ block: false });
  });

  it("does not raise skill_scan_failed when a failed scan returns no findings", () => {
    const manager = new SkillScanManager();

    const result = manager.shouldBlock(
      {
        status: "fail",
        updatedAt: Date.now(),
        findings: [],
      },
      "low",
    );

    expect(result).toMatchObject({ block: false });
  });
});
