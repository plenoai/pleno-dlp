export interface ScanOptions {
  /** Send candidates to providers for verification. Default false (offline). */
  verify?: boolean;
  /** Populate Finding.raw / raw_v2 with the plaintext secret. Default false. */
  includeRaw?: boolean;
  /** Restrict to these detector names (see detectors()). */
  detectors?: string[];
  concurrency?: number;
  /** scanPaths only: skip files larger than this many bytes. */
  maxFileSize?: number;
}

export interface Finding {
  detector: string;
  verified: boolean;
  verdict: 'verified' | 'unverified' | 'indeterminate' | string;
  assurance?: string;
  severity: string;
  redacted: string;
  raw?: string;
  raw_v2?: string;
  path?: string;
  line?: number;
  verify_error?: string;
  extra_data?: Record<string, string>;
}

export interface VerifyResult { detector: string; verified: boolean; error?: string }
export interface RevokeResult { detector: string; revoked: boolean; dry_run?: boolean; revoked_at?: string; provider_id?: string; note?: string }
export interface Detector { name: string; keywords: string[]; can_verify: boolean; can_revoke: boolean }

export type ErrorCode = 'unknown_detector' | 'not_supported' | 'not_confirmed' | 'invalid_argument' | 'internal';
export class PlenoDLPError extends Error {
  readonly code: ErrorCode;
}

export function apiVersion(): string;
export function detectors(): Detector[];
export function scanBytes(data: string | Uint8Array, options?: ScanOptions): Finding[];
export function scanPaths(paths: string | string[], options?: ScanOptions): Finding[];
export function verify(detector: string, secret: string): VerifyResult;
/** Irreversible. Exactly one of confirm / dryRun must be true. */
export function revoke(detector: string, secret: string, options: { confirm?: boolean; dryRun?: boolean }): RevokeResult;
