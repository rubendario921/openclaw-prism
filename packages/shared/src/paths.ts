import { isAbsolute, normalize, resolve } from "node:path";

/**
 * Canonicalize a file path using cwd context.
 * Used by Plugin runtime (path hook), Dashboard preview, and Dashboard apply
 * to ensure consistent path resolution across processes.
 *
 * Defence: if cwd is falsy or non-absolute, falls back to "/" to prevent
 * process.cwd()-dependent resolution drift across processes.
 *
 * NOTE: This is string-level canonicalization only (resolve + normalize).
 * It does NOT call fs.realpath — symlink aliases are not resolved.
 * See L-1 in dashboard-plan.md for rationale.
 */
export function canonicalizePath(rawPath: string, cwd: string): string {
  const safeCwd = cwd && isAbsolute(cwd) ? cwd : "/";
  return resolve(safeCwd, normalize(rawPath));
}
