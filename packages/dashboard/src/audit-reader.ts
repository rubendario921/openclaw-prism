import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { canonicalizePath } from "@kyaclaw/shared/paths";

export const DEFAULT_AUDIT_LOG = join(homedir(), ".openclaw", "security", "audit.jsonl");
export const AUDIT_WARNING_BYTES = 50 * 1024 * 1024;
export const CURSOR_PATTERN = /^[0-9a-f]{32}:[0-9]+$/;
export const MAX_CURSOR_OFFSET = 10_000_000;

export type AuditEntry = {
  fingerprint: string;
  lineOffset: number;
  cursor: string;
  record: Record<string, unknown>;
};

export type BlocksQuery = {
  cursor?: string;
  limit?: number;
  events?: string[];
  since?: string;
  session?: string;
  q?: string;
};

export type BlockPage = {
  blocks: AuditEntry[];
  nextCursor: string | null;
  hasMore: boolean;
  sizeWarning: boolean;
};

export class CursorNotFoundError extends Error {
  constructor(cursor: string) {
    super(`cursor not found: ${cursor}`);
    this.name = "CursorNotFoundError";
  }
}

function stripIntegrityFields(record: Record<string, unknown>): Record<string, unknown> {
  const { _hmac: _ignoreHmac, _hash: _ignoreHash, _prev: _ignorePrev, ...payload } = record;
  return payload;
}

function fingerprintRecord(record: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(record), "utf8").digest("hex").slice(0, 32);
}

function safeString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function enrichPathBlock(record: Record<string, unknown>): Record<string, unknown> {
  if (safeString(record.event) !== "path_block") return record;

  const next = { ...record };
  const hasRawPath = typeof next.rawPath === "string" && next.rawPath.length > 0;
  const hasLegacyPath = typeof next.path === "string" && next.path.length > 0;
  const legacyRecord = !hasRawPath && hasLegacyPath;

  const rawPath = hasRawPath ? String(next.rawPath) : hasLegacyPath ? String(next.path) : "";
  const rawCwd = safeString(next.cwd);
  const cwd = rawCwd && isAbsolute(rawCwd) ? rawCwd : "/";

  if (rawPath) {
    next.rawPath = rawPath;
    next.cwd = cwd;
    next.canonicalPath = canonicalizePath(rawPath, cwd);
  }
  if (legacyRecord || !rawCwd) {
    next.legacyRecord = true;
  }

  return next;
}

function parseAuditLine(line: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(line) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function isBlockEvent(event: string): boolean {
  return event.includes("block");
}

export function parseCursor(cursor: string): { fingerprint: string; lineOffset: number } | null {
  if (!CURSOR_PATTERN.test(cursor)) return null;
  const [fingerprint, offsetRaw] = cursor.split(":");
  const lineOffset = Number(offsetRaw);
  if (!Number.isInteger(lineOffset) || lineOffset < 0) return null;
  if (lineOffset > MAX_CURSOR_OFFSET) return null;
  return { fingerprint, lineOffset };
}

export function readAuditEntries(opts?: {
  auditLogPath?: string;
  warningThresholdBytes?: number;
}): { entries: AuditEntry[]; sizeWarning: boolean } {
  const auditLogPath = opts?.auditLogPath ?? process.env.PRISM_AUDIT_LOG ?? DEFAULT_AUDIT_LOG;
  const warningThresholdBytes = opts?.warningThresholdBytes ?? AUDIT_WARNING_BYTES;
  if (!existsSync(auditLogPath)) {
    return { entries: [], sizeWarning: false };
  }

  const stat = statSync(auditLogPath);
  const sizeWarning = stat.size >= warningThresholdBytes;

  const seen = new Map<string, number>();
  const entries: AuditEntry[] = [];
  const lines = readFileSync(auditLogPath, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  for (const line of lines) {
    const parsed = parseAuditLine(line);
    if (!parsed) continue;
    const stripped = stripIntegrityFields(parsed);
    const fingerprint = fingerprintRecord(stripped);
    const lineOffset = seen.get(fingerprint) ?? 0;
    seen.set(fingerprint, lineOffset + 1);

    entries.push({
      fingerprint,
      lineOffset,
      cursor: `${fingerprint}:${lineOffset}`,
      record: enrichPathBlock(stripped),
    });
  }

  return { entries, sizeWarning };
}

function matchesFilters(record: Record<string, unknown>, query: BlocksQuery): boolean {
  const event = safeString(record.event);
  const eventFilter = query.events?.filter(Boolean);
  if (eventFilter && eventFilter.length > 0) {
    if (!eventFilter.includes(event)) return false;
  } else if (!isBlockEvent(event)) {
    return false;
  }

  if (query.since) {
    const sinceMs = Date.parse(query.since);
    if (!Number.isFinite(sinceMs)) return false;
    const tsMs = Date.parse(safeString(record.ts));
    if (!Number.isFinite(tsMs) || tsMs < sinceMs) return false;
  }

  if (query.session) {
    if (safeString(record.session) !== query.session) return false;
  }

  if (query.q) {
    const haystack = JSON.stringify(record).toLowerCase();
    if (!haystack.includes(query.q.toLowerCase())) return false;
  }

  return true;
}

export function listBlockEvents(opts?: {
  auditLogPath?: string;
  warningThresholdBytes?: number;
  query?: BlocksQuery;
}): BlockPage {
  const query = opts?.query ?? {};
  const limitRaw = Number(query.limit ?? 100);
  const limit = Number.isFinite(limitRaw) && limitRaw > 0
    ? Math.min(1000, Math.floor(limitRaw))
    : 100;

  const { entries, sizeWarning } = readAuditEntries({
    auditLogPath: opts?.auditLogPath,
    warningThresholdBytes: opts?.warningThresholdBytes,
  });

  const filtered = entries
    .slice()
    .reverse()
    .filter((entry) => matchesFilters(entry.record, query));

  let start = 0;
  if (query.cursor) {
    const idx = filtered.findIndex((entry) => entry.cursor === query.cursor);
    if (idx < 0) throw new CursorNotFoundError(query.cursor);
    start = idx + 1;
  }

  const page = filtered.slice(start, start + limit);
  const hasMore = start + page.length < filtered.length;
  const nextCursor = hasMore && page.length > 0
    ? page[page.length - 1]!.cursor
    : null;

  return { blocks: page, nextCursor, hasMore, sizeWarning };
}

export function findEntryByCursor(
  sourceCursor: string,
  opts?: { auditLogPath?: string; warningThresholdBytes?: number },
): AuditEntry | null {
  const { entries } = readAuditEntries({
    auditLogPath: opts?.auditLogPath,
    warningThresholdBytes: opts?.warningThresholdBytes,
  });
  return entries.find((entry) => entry.cursor === sourceCursor) ?? null;
}
