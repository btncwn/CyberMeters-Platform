#!/usr/bin/env node
//
// Microsoft SSO nOAuth guard (P0 #6). Two layers must hold:
//  1. JWT layer — a single-tenant config (specific tenant GUID) rejects any
//     token whose tid is a different tenant (so a foreign-tenant nOAuth token
//     never validates). A multi-tenant alias deliberately accepts any tid.
//  2. Linking layer — email-based auto-linking to an existing local account is
//     only safe under a single-tenant config (org-controlled email); the route
//     gates it on isSingleTenantConfig. This proves the gate value the route
//     keys that decision on.
// Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const jwt = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "microsoft-jwt.js")).href);
const { isSingleTenantConfig, validateMicrosoftIdTokenClaims } = jwt;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };
const throws = (fn, re) => { try { fn(); return false; } catch (e) { return re ? re.test(e.message) : true; } };

// ── isSingleTenantConfig (the value the linking gate keys on) ─────────────────
ok("'common' is multi-tenant → email-linking OFF", isSingleTenantConfig("common") === false);
ok("'organizations' is multi-tenant → OFF", isSingleTenantConfig("organizations") === false);
ok("'consumers' is multi-tenant → OFF", isSingleTenantConfig("consumers") === false);
ok("alias check is case-insensitive", isSingleTenantConfig("COMMON") === false);
ok("a specific tenant GUID is single-tenant → email-linking ALLOWED", isSingleTenantConfig("6804d501-aa79-4919-affe-2f457d858d8e") === true);
ok("empty/missing tenant is treated as single-tenant (never accidentally multi)", isSingleTenantConfig("") === true);

// ── JWT-layer tid enforcement ─────────────────────────────────────────────────
const CID = "client-1";
const TENANT = "11111111-1111-1111-1111-111111111111";
const header = { alg: "RS256", kid: "k1" };
const payload = (tid) => ({ aud: CID, exp: 9_999_999_999, oid: "oid-1", tid,
  iss: `https://login.microsoftonline.com/${tid}/v2.0` });

ok("single-tenant REJECTS a foreign-tenant token (nOAuth blocked at the JWT layer)",
   throws(() => validateMicrosoftIdTokenClaims(header, payload("22222222-2222-2222-2222-222222222222"), CID, TENANT), /tenant mismatch/));
ok("single-tenant ACCEPTS its own tenant's token",
   !throws(() => validateMicrosoftIdTokenClaims(header, payload(TENANT), CID, TENANT)));
ok("multi-tenant config accepts ANY tenant's tid (exactly why email-linking must be gated in the route)",
   !throws(() => validateMicrosoftIdTokenClaims(header, payload("33333333-3333-3333-3333-333333333333"), CID, "common")));
ok("aud mismatch is still rejected",
   throws(() => validateMicrosoftIdTokenClaims(header, { ...payload(TENANT), aud: "other" }, CID, TENANT), /aud/));
ok("missing oid is rejected",
   throws(() => validateMicrosoftIdTokenClaims(header, { ...payload(TENANT), oid: undefined }, CID, TENANT), /oid/));

// ── The route wires the gate to isSingleTenantConfig (guard against drift) ─────
const authSrc = await import("node:fs").then((fs) => fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "auth.js"), "utf8"));
ok("route gates the email-link block on tenant trust", /tenantTrusted\s*=\s*isSingleTenantConfig\(/.test(authSrc));
ok("route only email-matches when trusted (!user && tenantTrusted)", /if \(!user && tenantTrusted\)/.test(authSrc));

console.log(`\nSSO linking guard: ${pass}/${pass + fail} passed`);
if (fail) { console.error("sso-linking-guard validation FAILED"); process.exit(1); }
console.log("sso-linking-guard validation passed");
