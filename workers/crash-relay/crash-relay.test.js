// Contract test for the vendored relay. It loads the SAME published schema
// the Go client test loads (pkg/telemetry/crash/schema) and fails if the
// relay's allowlist or required set drifts from it. Run with:
//
//   node --test workers/crash-relay/crash-relay.test.js
//
// CI runs this on every push/PR alongside `go test ./pkg/telemetry/crash`.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ALLOWED_FIELDS,
  REQUIRED_FIELDS,
  SCHEMA,
  validate,
} from "./crash-relay.js";

const schema = JSON.parse(
  readFileSync(
    new URL(
      "../../pkg/telemetry/crash/schema/pleno-dlp.crash.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function wellFormed() {
  return {
    schema: "pleno-dlp.crash/v1",
    fingerprint: "0123456789abcdef",
    version: "v0.67.0",
    commit: "abc123",
    goos: "linux",
    goarch: "amd64",
    go_version: "go1.26.9",
    command: "scan filesystem",
    flags: ["json"],
    kind: "panic",
    message: "panic: boom",
    stack: "goroutine [running]:",
    created_at: "2026-10-18T00:00:00Z",
  };
}

test("relay allowlist matches the published schema", () => {
  assert.deepEqual(
    [...ALLOWED_FIELDS].sort(),
    Object.keys(schema.properties).sort(),
    "relay ALLOWED_FIELDS drifted from schema properties",
  );
  assert.deepEqual(
    [...REQUIRED_FIELDS].sort(),
    [...schema.required].sort(),
    "relay REQUIRED_FIELDS drifted from schema required",
  );
  assert.equal(SCHEMA, schema.$id);
  assert.equal(schema.additionalProperties, false);
});

test("validate accepts a well-formed report", () => {
  assert.deepEqual(validate(wellFormed()), { ok: true });
});

test("validate accepts empty strings and no flags", () => {
  const minimal = wellFormed();
  minimal.commit = "";
  minimal.stack = "";
  minimal.message = "";
  minimal.flags = [];
  assert.deepEqual(validate(minimal), { ok: true });
});

test("validate rejects unknown fields so secrets cannot be smuggled", () => {
  const payload = wellFormed();
  payload.secret = "contents of a scanned file the client must never send";
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /unknown field: secret/);
});

test("validate rejects a missing required field", () => {
  const payload = wellFormed();
  delete payload.message;
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /message/);
});

test("validate rejects a foreign schema", () => {
  const payload = wellFormed();
  payload.schema = "pleno-dlp.crash/v2";
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /unsupported schema/);
});

test("validate rejects non-object bodies", () => {
  for (const value of [null, "string", 42, [], undefined]) {
    const result = validate(value);
    assert.equal(result.ok, false, `expected rejection for ${String(value)}`);
  }
});

test("validate rejects malformed flags", () => {
  const payload = wellFormed();
  payload.flags = "json";
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /flags/);
});
