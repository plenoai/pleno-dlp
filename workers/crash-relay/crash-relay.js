// Vendored copy of the plenoai/plenoai.com crash relay's validate() path
// (workers/crash-relay/crash-relay.js). It exists in this repo only so the
// client <-> relay contract can be exercised by CI here. The published
// schema in pkg/telemetry/crash/schema/pleno-dlp.crash.v1.json is the
// single source of truth; crash-relay.test.js fails if this allowlist
// drifts from it. When upstream changes validate(), re-vendor it here in
// the same PR that updates the schema.

export const SCHEMA = "pleno-dlp.crash/v1";

// Every key the relay will accept. Anything else is rejected outright so a
// client cannot smuggle scanned file content or secret material.
export const ALLOWED_FIELDS = Object.freeze([
  "schema",
  "fingerprint",
  "version",
  "commit",
  "goos",
  "goarch",
  "go_version",
  "command",
  "flags",
  "kind",
  "message",
  "stack",
  "created_at",
]);

// Keys every report must carry. Every pleno-dlp.crash/v1 field is required
// (the Go client never omits a field), so this mirrors ALLOWED_FIELDS.
export const REQUIRED_FIELDS = Object.freeze([
  "schema",
  "fingerprint",
  "version",
  "commit",
  "goos",
  "goarch",
  "go_version",
  "command",
  "flags",
  "kind",
  "message",
  "stack",
  "created_at",
]);

const ALLOWED = new Set(ALLOWED_FIELDS);
const STRING_FIELDS = ALLOWED_FIELDS.filter((field) => field !== "flags");

/**
 * Validate a decoded crash report against the pleno-dlp.crash/v1 contract.
 * @param {unknown} payload
 * @returns {{ok: true} | {ok: false, error: string}}
 */
export function validate(payload) {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return { ok: false, error: "body must be a JSON object" };
  }
  for (const key of Object.keys(payload)) {
    if (!ALLOWED.has(key)) {
      return { ok: false, error: `unknown field: ${key}` };
    }
  }
  for (const key of REQUIRED_FIELDS) {
    if (payload[key] === null || payload[key] === undefined) {
      return { ok: false, error: `missing required field: ${key}` };
    }
  }
  if (!Array.isArray(payload.flags) || payload.flags.some((f) => typeof f !== "string")) {
    return { ok: false, error: "flags must be an array of strings" };
  }
  for (const key of STRING_FIELDS) {
    if (typeof payload[key] !== "string") {
      return { ok: false, error: `field ${key} must be a string` };
    }
  }
  if (payload.schema !== SCHEMA) {
    return { ok: false, error: `unsupported schema: ${payload.schema}` };
  }
  return { ok: true };
}

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return new Response("method not allowed", { status: 405 });
    }
    let payload;
    try {
      payload = await request.json();
    } catch {
      return new Response("invalid JSON", { status: 400 });
    }
    const result = validate(payload);
    if (!result.ok) {
      return new Response(result.error, { status: 422 });
    }
    return new Response(null, { status: 202 });
  },
};
