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
});

test("schema rejects extra properties", () => {
  assert.equal(
    schema.additionalProperties,
    false,
    "schema must set additionalProperties=false so the relay allowlist is closed",
  );
});

test("schema kind enum matches the kinds the client can emit", () => {
  assert.deepEqual(
    [...schema.properties.kind.enum].sort(),
    ["fatal", "panic", "recovered"],
    "schema kind enum drifted from the Go Kind constants",
  );
});

test("well-formed report is accepted", () => {
  assert.deepEqual(validate(wellFormed()), { ok: true });
});

test("unknown field is rejected", () => {
  const payload = wellFormed();
  payload.secret = "-----BEGIN PRIVATE KEY-----";
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /unknown field: secret/);
});

test("every required field missing in turn is rejected", () => {
  for (const key of REQUIRED_FIELDS) {
    const payload = wellFormed();
    delete payload[key];
    const result = validate(payload);
    assert.equal(result.ok, false, `missing ${key} was accepted`);
    assert.match(result.error, new RegExp(`missing required field: ${key}`));
  }
});

test("null required field is rejected", () => {
  const payload = wellFormed();
  payload.message = null;
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /missing required field: message/);
});

test("non-object bodies are rejected", () => {
  for (const payload of [null, [], "report", 42, true]) {
    const result = validate(payload);
    assert.equal(result.ok, false, `${JSON.stringify(payload)} was accepted`);
  }
});

test("unsupported schema is rejected", () => {
  const payload = wellFormed();
  payload.schema = "pleno-dlp.crash/v2";
  const result = validate(payload);
  assert.equal(result.ok, false);
  assert.match(result.error, /unsupported schema: pleno-dlp\.crash\/v2/);
});

test("flags must be an array of strings", () => {
  const notArray = wellFormed();
  notArray.flags = "json";
  assert.equal(validate(notArray).ok, false);

  const notStrings = wellFormed();
  notStrings.flags = ["json", 7];
  const result = validate(notStrings);
  assert.equal(result.ok, false);
  assert.match(result.error, /flags must be an array of strings/);
});

test("string fields must be strings", () => {
  for (const key of ALLOWED_FIELDS) {
    if (key === "flags") continue;
    const payload = wellFormed();
    payload[key] = 42;
    const result = validate(payload);
    assert.equal(result.ok, false, `non-string ${key} was accepted`);
    assert.match(result.error, new RegExp(`field ${key} must be a string`));
  }
});

test("fetch accepts a valid POST and rejects bad requests", async () => {
  const okResponse = await relay.fetch(
    new Request("https://crash.plenoai.com/v1/pleno-dlp", {
      method: "POST",
      body: JSON.stringify(wellFormed()),
    }),
  );
  assert.equal(okResponse.status, 202);

  const badPayload = await relay.fetch(
    new Request("https://crash.plenoai.com/v1/pleno-dlp", {
      method: "POST",
      body: JSON.stringify({ schema: "pleno-dlp.crash/v1" }),
    }),
  );
  assert.equal(badPayload.status, 422);

  const invalidJSON = await relay.fetch(
    new Request("https://crash.plenoai.com/v1/pleno-dlp", {
      method: "POST",
      body: "not json",
    }),
  );
  assert.equal(invalidJSON.status, 400);

  const wrongMethod = await relay.fetch(
    new Request("https://crash.plenoai.com/v1/pleno-dlp", { method: "GET" }),
  );
  assert.equal(wrongMethod.status, 405);
});
