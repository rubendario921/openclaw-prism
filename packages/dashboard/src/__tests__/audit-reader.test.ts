import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { listBlockEvents, readAuditEntries } from "../audit-reader.js";

function writeAuditLog(lines: Array<Record<string, unknown>>): string {
  const dir = mkdtempSync(join(tmpdir(), "prism-dashboard-audit-"));
  const path = join(dir, "audit.jsonl");
  writeFileSync(path, `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`, "utf8");
  return path;
}

describe("audit-reader", () => {
  it("computes fingerprint/cursor with absolute lineOffset", () => {
    const duplicate = {
      ts: "2026-03-06T12:00:00.000Z",
      event: "exec_whitelist_block",
      command: "curl https://example.com",
      session: "sess-a",
    };
    const auditPath = writeAuditLog([
      { ...duplicate, _hmac: "one", _hash: "a" },
      { ts: "2026-03-06T12:01:00.000Z", event: "risk_escalation_block", session: "sess-b" },
      { ...duplicate, _hmac: "two", _hash: "b" },
    ]);

    const { entries } = readAuditEntries({ auditLogPath: auditPath });
    expect(entries).toHaveLength(3);
    expect(entries[0]!.lineOffset).toBe(0);
    expect(entries[2]!.lineOffset).toBe(1);
    expect(entries[0]!.fingerprint).toBe(entries[2]!.fingerprint);
    expect(entries[0]!.record).not.toHaveProperty("_hmac");
    expect(entries[0]!.record).not.toHaveProperty("_hash");
  });

  it("enriches path_block records and marks legacy records", () => {
    const auditPath = writeAuditLog([
      {
        ts: "2026-03-06T12:00:00.000Z",
        event: "path_block",
        rawPath: "../etc/hosts",
        cwd: "/home/user/project",
      },
      {
        ts: "2026-03-06T12:01:00.000Z",
        event: "path_block",
        path: "../legacy/hosts",
      },
    ]);
    const { entries } = readAuditEntries({ auditLogPath: auditPath });
    expect(entries[0]!.record.canonicalPath).toBe("/home/user/etc/hosts");
    expect(entries[1]!.record.legacyRecord).toBe(true);
    expect(entries[1]!.record.cwd).toBe("/");
  });

  it("supports event filtering and cursor pagination", () => {
    const auditPath = writeAuditLog([
      { ts: "2026-03-06T12:00:00.000Z", event: "exec_whitelist_block", command: "curl x", session: "s1" },
      { ts: "2026-03-06T12:01:00.000Z", event: "path_block", rawPath: "/etc/hosts", cwd: "/" },
      { ts: "2026-03-06T12:02:00.000Z", event: "exec_whitelist_block", command: "git status", session: "s2" },
    ]);

    const page1 = listBlockEvents({
      auditLogPath: auditPath,
      query: { limit: 1, events: ["exec_whitelist_block"] },
    });
    expect(page1.blocks).toHaveLength(1);
    expect(page1.blocks[0]!.record.command).toBe("git status");
    expect(page1.hasMore).toBe(true);
    expect(page1.nextCursor).toBeTruthy();

    const page2 = listBlockEvents({
      auditLogPath: auditPath,
      query: { limit: 1, events: ["exec_whitelist_block"], cursor: page1.nextCursor ?? undefined },
    });
    expect(page2.blocks).toHaveLength(1);
    expect(page2.blocks[0]!.record.command).toBe("curl x");
    expect(page2.hasMore).toBe(false);
  });

  it("sets size warning when file exceeds threshold", () => {
    const auditPath = writeAuditLog([
      { ts: "2026-03-06T12:00:00.000Z", event: "exec_whitelist_block", command: "curl x" },
    ]);
    const result = listBlockEvents({
      auditLogPath: auditPath,
      warningThresholdBytes: 1,
      query: { limit: 10 },
    });
    expect(result.sizeWarning).toBe(true);
  });
});
