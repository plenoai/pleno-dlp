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
  assert.equal(SCHEMA, schema.$id);
  assert.equal(schema.additionalProperties, false);
});

test("relay schema identifier matches the schema const", () => {
  assert.equal(SCHEMA, schema.properties.schema.const);
});

test("relay accepts a well-formed report", () => {
  assert.deepEqual(validate(wellFormed()), { ok: true });
});

test("relay rejects unknown fields", () => {
  const payload = { ...wellFormed(), scanned_content: "AKIA..." };
  const result = validate(payload);
  assert.equal(result.ok, false, "an extra field was accepted");
  assert.match(result.error, /unknown field: scanned_content/);
});

test("relay rejects every missing required field", () => {
  for (const key of REQUIRED_FIELDS) {
    const payload = wellFormed();
    delete payload[key];
    const result = validate(payload);
    assert.equal(result.ok, false, `missing ${key} was accepted`);
    assert.match(result.error, new RegExp(`missing required field: ${key}`));
  }
});

test("relay rejects a wrong schema identifier", () => {
  const result = validate({ ...wellFormed(), schema: "pleno-dlp.crash/v2" });
  assert.equal(result.ok, false);
  assert.match(result.error, /unsupported schema/);
});

test("relay rejects non-object bodies", () => {
  for (const payload of [null, "string", 42, [], true]) {
    assert.equal(validate(payload).ok, false, `accepted ${JSON.stringify(payload)}`);
  }
});

test("relay rejects non-string scalar fields", () => {
  for (const key of ALLOWED_FIELDS) {
    if (key === "flags") continue;
    const payload = wellFormed();
    payload[key] = { nested: true };
    const result = validate(payload);
    assert.equal(result.ok, false, `field ${key} accepted a non-string`);
    assert.match(result.error, new RegExp(`field ${key} must be a string`));
  }
});

test("relay rejects flags that are not an array of strings", () => {
  assert.equal(validate({ ...wellFormed(), flags: "json" }).ok, false);
  assert.equal(validate({ ...wellFormed(), flags: ["json", 7] }).ok, false);
});

test("relay kind enum matches the client's kinds", () => {
  assert.deepEqual([...schema.properties.kind.enum].sort(), [
    "fatal",
    "panic",
    "recovered",
  ]);
});

test("relay fetch accepts a valid POST with 202", async () => {
  const request = new Request("https://crash.plenoai.com/v1/pleno-dlp", {
    method: "POST",
    body: JSON.stringify(wellFormed()),
  });
  const response = await relay.fetch(request);
  assert.equal(response.status, 202);
});

test("relay fetch rejects an unknown field with 422", async () => {
  const request = new Request("https://crash.plenoai.com/v1/pleno-dlp", {
    method: "POST",
    body: JSON.stringify({ ...wellFormed(), env: "SECRET=x" }),
  });
  const response = await relay.fetch(request);
  assert.equal(response.status, 422);
});

test("relay fetch rejects a non-POST with 405", async () => {
  const request = new Request("https://crash.plenoai.com/v1/pleno-dlp", {
    method: "GET",
  });
  const response = await relay.fetch(request);
  assert.equal(response.status, 405);
});

test("relay fetch rejects malformed JSON with 400", async () => {
  const request = new Request("https://crash.plenoai.com/v1/pleno-dlp", {
    method: "POST",
    body: "{not json",
  });
  const response = await relay.fetch(request);
  assert.equal(response.status, 400);
});
