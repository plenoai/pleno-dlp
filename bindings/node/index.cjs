'use strict';
// Node.js bindings for pleno-dlp's stable embeddable API (docs/library.md).
// The bundled libpleno_dlp shared library is loaded through koffi; set
// PLENO_DLP_LIBRARY to load a library from another path.
const path = require('node:path');
const fs = require('node:fs');
const koffi = require('koffi');

class PlenoDLPError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'PlenoDLPError';
    this.code = code;
  }
}

function libraryPath() {
  if (process.env.PLENO_DLP_LIBRARY) return process.env.PLENO_DLP_LIBRARY;
  const ext = process.platform === 'darwin' ? 'dylib' : 'so';
  return path.join(__dirname, 'lib', `${process.platform}-${process.arch}`, `libpleno_dlp.${ext}`);
}

let native;
function load() {
  if (native) return native;
  const p = libraryPath();
  if (!fs.existsSync(p)) {
    throw new Error(`pleno-dlp native library not found at ${p} (${process.platform}-${process.arch} may be unsupported)`);
  }
  const lib = koffi.load(p);
  // Return void* so the Go-allocated string can be released with pleno_dlp_free.
  native = {
    version: lib.func('void *pleno_dlp_version()'),
    detectors: lib.func('void *pleno_dlp_detectors()'),
    scanBytes: lib.func('void *pleno_dlp_scan_bytes(const uint8_t *data, int64_t n, const char *opts)'),
    scanPaths: lib.func('void *pleno_dlp_scan_paths(const char *paths, const char *opts)'),
    verify: lib.func('void *pleno_dlp_verify(const char *detector, const char *secret)'),
    revoke: lib.func('void *pleno_dlp_revoke(const char *detector, const char *secret, const char *opts)'),
    free: lib.func('void pleno_dlp_free(void *p)'),
  };
  return native;
}

function call(fn, ...args) {
  const n = load();
  const ptr = n[fn](...args);
  let raw;
  try {
    raw = koffi.decode(ptr, 'char', -1);
  } finally {
    n.free(ptr);
  }
  const env = JSON.parse(raw);
  if (env.error) throw new PlenoDLPError(env.error.code, env.error.message);
  return env.ok;
}

function scanOpts(o = {}) {
  const out = { verify: !!o.verify, include_raw: !!o.includeRaw };
  if (o.detectors && o.detectors.length) out.detectors = [...o.detectors];
  if (o.concurrency) out.concurrency = o.concurrency;
  if (o.maxFileSize) out.max_file_size = o.maxFileSize;
  return JSON.stringify(out);
}

function apiVersion() {
  return call('version');
}

function detectors() {
  return call('detectors');
}

function scanBytes(data, options) {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return call('scanBytes', buf, buf.length, scanOpts(options));
}

function scanPaths(paths, options) {
  const list = Array.isArray(paths) ? paths.map(String) : [String(paths)];
  return call('scanPaths', JSON.stringify(list), scanOpts(options));
}

function verify(detector, secret) {
  return call('verify', detector, secret);
}

function revoke(detector, secret, options = {}) {
  return call('revoke', detector, secret, JSON.stringify({ confirm: !!options.confirm, dry_run: !!options.dryRun }));
}

module.exports = { PlenoDLPError, apiVersion, detectors, scanBytes, scanPaths, verify, revoke };
