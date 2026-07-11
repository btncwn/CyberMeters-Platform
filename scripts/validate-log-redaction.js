#!/usr/bin/env node
//
// Verifies the central log-redaction helper (lib/redact.js) scrubs secret-shaped
// keys AND values, so nothing sensitive reaches the logs. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { redact, redactedJson } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "redact.js")).href
);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };
const hides = (obj, ...needles) => { const s = redactedJson(obj); return needles.every((n) => !s.includes(n)); };

// Secret KEYS are redacted regardless of value.
ok("password key redacted",      hides({ password: "hunter2" }, "hunter2"));
ok("token key redacted",         hides({ session_token: "abc123def456" }, "abc123def456"));
ok("authorization key redacted", hides({ authorization: "Bearer xyztoken12345" }, "xyztoken12345"));
ok("api_key key redacted",       hides({ api_key: "supersecretvalue" }, "supersecretvalue"));
ok("mfa/totp key redacted",      hides({ totp_secret: "JBSWY3DPEHPK3PXP" }, "JBSWY3DPEHPK3PXP"));
ok("nested secret redacted",     hides({ user: { profile: { recovery_code: "AAAA-BBBB" } } }, "AAAA-BBBB"));

// Secret VALUES are redacted even under an innocent key.
ok("JWT value redacted",         hides({ note: "eyJhbGciOiJ.eyJzdWIiOiIx.SflKxwRJSMeK" }, "SflKxwRJSMeK"));
ok("stripe key value redacted",  hides({ data: "sk_live_ABC123DEF456GHI" }, "sk_live_ABC123DEF456GHI"));
ok("whsec value redacted",       hides({ x: "whsec_1234567890abcdef" }, "whsec_1234567890abcdef"));
ok("cm token value redacted",    hides({ x: "cmrua_0102019f46e701e3aa" }, "cmrua_0102019f46e701e3aa"));
ok("bearer value redacted",      hides({ msg: "got Bearer abcdef1234567890" }, "abcdef1234567890"));
ok("long hex value redacted",    hides({ h: "a".repeat(64) }, "a".repeat(64)));

// Non-secrets survive (redaction must not destroy useful log context).
const safe = redactedJson({ request_id: "req_123", scope: "auth/login", status: 500, email: "user@example.com" });
ok("keeps request_id",  safe.includes("req_123"));
ok("keeps scope",       safe.includes("auth/login"));
ok("keeps status",      safe.includes("500"));

// Robustness: cycles and depth don't throw/hang.
const cyc = {}; cyc.self = cyc;
ok("cycle-safe", (() => { try { redact(cyc); return true; } catch { return false; } })());
ok("null/undefined safe", redact(null) === null && redact(undefined) === undefined);

console.log(`\nLog redaction: ${pass}/${pass + fail} passed`);
if (fail) { console.error("log-redaction validation FAILED"); process.exit(1); }
console.log("log-redaction validation passed");
