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

import relay, {
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
  assert.equal(SCHEMA, schema.$id, "relay SCHEMA drifted from schema $id");
  assert.equal(
    schema.additionalProperties,
    false,
    "schema must set additionalProperties=false so the relay allowlist stays closed",
  );
});

test("validate accepts a well-formed report", () => {
  assert.deepEqual(validate(wellFormed()), { ok: true });
});

test("validate accepts a report with every optional string blank", () => {
  const payload = wellFormed();
  payload.commit = "";
  payload.stack = "";
  payload.command = "";
  payload.flags = [];
  assert.deepEqual(validate(payload), { ok: true });
});

test("validate rejects a payload that is not an object", () => {
  for (const bad of [null, [], "report", 42, true]) {
    const result = validate(bad);
    assert.equal(result.ok, false, `expected rejection for ${JSON.stringify(bad)}`);
  }
});

test("validate rejects an unknown field (closed allowlist)", () => {
  const payload = wellFormed();
  payload.secret = "AKIAIOSFODNN7EXAMPLE";
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /unknown field/);
});

test("validate rejects a missing required field", () => {
  for (const field of REQUIRED_FIELDS) {
    const payload = wellFormed();
    delete payload[field];
    const result = validate(payload);
    assert.equal(result.ok, false, `expected rejection when ${field} is missing`);
    assert.match(result.error, /missing required field/);
  }
});

test("validate rejects a non-string string field", () => {
  const payload = wellFormed();
  payload.message = { nested: "not a string" };
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /message/);
});

test("validate rejects flags that are not an array of strings", () => {
  const notArray = wellFormed();
  notArray.flags = "json";
  assert.equal(validate(notArray).ok, false);

  const badItem = wellFormed();
  badItem.flags = ["json", 7];
  assert.equal(validate(badItem).ok, false);
});

test("validate rejects an unsupported schema identifier", () => {
  const payload = wellFormed();
  payload.schema = "pleno-dlp.crash/v2";
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /unsupported schema/);
});

test("fetch handler enforces method, JSON, contract, and success", async () => {
  const get = await relay.fetch(new Request("https://crash.plenoai.com/v1/pleno-dlp"));
  assert.equal(get.status, 405);

  const invalidJSON = await relay.fetch(
    new Request("https://crash.plenoai.com/v1/pleno-dlp", {
      method: "POST",
      body: "{not json",
    }),
  );
  assert.equal(invalidJSON.status, 400);

  const rejected = await relay.fetch(
    new Request("https://crash.plenoai.com/v1/pleno-dlp", {
      method: "POST",
      body: JSON.stringify({ ...wellFormed(), extra: "nope" }),
    }),
  );
  assert.equal(rejected.status, 422);

  const accepted = await relay.fetch(
    new Request("https://crash.plenoai.com/v1/pleno-dlp", {
      method: "POST",
      body: JSON.stringify(wellFormed()),
    }),
  );
  assert.equal(accepted.status, 202);
});
