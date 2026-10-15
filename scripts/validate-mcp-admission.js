#!/usr/bin/env node
import assert from "node:assert/strict";
import { evaluateMcpAdmission, MCP_DENY } from "../workers/scan-api/src/routes/mcp-authz.js";

const NOW = Date.parse("2026-10-15T12:00:00.000Z");
const FUTURE = "2026-10-16T12:00:00.000Z";
const SECRET = "cm_live_SUPERSECRETBEARER";

const base = () => ({
  requestedWorkspaceId: "ws_1",
  identity: {
    kind: "api_token", tokenId: "tok_1", userId: "usr_1", status: "active",
    scope: "read", workspaceId: "ws_1", expiresAt: FUTURE,
    bearer: SECRET, email: "a@example.com", name: "Alice Secret",
  },
  user: { id: "usr_1", status: "active", email: "a@example.com", name: "Alice Secret" },
  workspace: { id: "ws_1", deletedAt: null, ownerUserId: "usr_other", memberCount: 1 },
  membership: { role: "analyst" },
  entitlement: { mcp: true },
});
const run = (mut) => { const i = base(); mut?.(i); return evaluateMcpAdmission(i, NOW); };
const expectDeny = (name, mut, reason) => {
  const d = run(mut);
  assert.equal(d.allowed, false, name);
  assert.equal(d.reason, reason, name);
  assert.equal(d.grant, null, name);
};

// Positive
for (const role of ["viewer", "analyst", "admin", "owner"]) {
  const d = run((i) => { i.membership.role = role; });
  assert.equal(d.allowed, true, role);
  assert.deepEqual(d.grant, {
    tokenId: "tok_1", userId: "usr_1", workspaceId: "ws_1", role, scope: "read", expiresAt: FUTURE,
  });
  assert.deepEqual(Object.keys(d.grant).sort(), ["expiresAt", "role", "scope", "tokenId", "userId", "workspaceId"]);
}
const legacy = run((i) => { i.membership = null; i.workspace.ownerUserId = "usr_1"; i.workspace.memberCount = 0; });
assert.equal(legacy.allowed, true);
assert.equal(legacy.grant.role, "owner");
assert.equal(run((i) => { i.identity.expiresAt = NOW + 60_000; }).allowed, true);

// Identity / token
expectDeny("missing identity", (i) => { delete i.identity; }, MCP_DENY.IDENTITY_NOT_API_TOKEN);
expectDeny("null identity", (i) => { i.identity = null; }, MCP_DENY.IDENTITY_NOT_API_TOKEN);
expectDeny("session identity", (i) => { i.identity.kind = "session"; }, MCP_DENY.IDENTITY_NOT_API_TOKEN);
for (const s of ["revoked", "disabled", "expired", "", undefined, null]) {
  expectDeny(`status ${s}`, (i) => { i.identity.status = s; }, MCP_DENY.TOKEN_NOT_ACTIVE);
}
for (const s of ["write", "admin", "read ", "READ", "read write", "", undefined, ["read"]]) {
  expectDeny(`scope ${JSON.stringify(s)}`, (i) => { i.identity.scope = s; }, MCP_DENY.SCOPE_NOT_PERMITTED);
}
for (const w of [null, undefined, ""]) {
  expectDeny(`unbound ${w}`, (i) => { i.identity.workspaceId = w; }, MCP_DENY.TOKEN_UNBOUND);
}
expectDeny("wrong workspace", (i) => { i.identity.workspaceId = "ws_2"; }, MCP_DENY.WORKSPACE_BINDING_MISMATCH);
expectDeny("never infer from membership", (i) => { i.identity.workspaceId = null; i.membership = { role: "owner" }; }, MCP_DENY.TOKEN_UNBOUND);

// Expiry
for (const e of [null, undefined, "", "never", "not-a-date", "2026-13-99", NaN, Infinity, -1, 0, 1.5, 1e20, 8_640_000_000_000_001, {}, true]) {
  expectDeny(`expiry ${String(e)}`, (i) => { i.identity.expiresAt = e; }, MCP_DENY.TOKEN_EXPIRY_INVALID);
}
for (const e of ["2027-02-30T12:00:00.000Z", "2026-10-16T12:00:00Z", "2026-10-16T12:00:00.000+00:00"] ) {
  assert.doesNotThrow(() => expectDeny(`non-canonical expiry ${e}`, (i) => { i.identity.expiresAt = e; }, MCP_DENY.TOKEN_EXPIRY_INVALID));
}
expectDeny("past expiry", (i) => { i.identity.expiresAt = "2026-10-14T00:00:00.000Z"; }, MCP_DENY.TOKEN_EXPIRED);
expectDeny("equal-now expiry", (i) => { i.identity.expiresAt = NOW; }, MCP_DENY.TOKEN_EXPIRED);
expectDeny("equal-now ISO expiry", (i) => { i.identity.expiresAt = new Date(NOW).toISOString(); }, MCP_DENY.TOKEN_EXPIRED);

// User
for (const s of ["suspended", "disabled", "", undefined]) {
  expectDeny(`user ${s}`, (i) => { i.user.status = s; }, MCP_DENY.USER_NOT_ACTIVE);
}
expectDeny("missing user", (i) => { i.user = null; }, MCP_DENY.USER_NOT_ACTIVE);
expectDeny("user/token mismatch", (i) => { i.user.id = "usr_9"; }, MCP_DENY.USER_NOT_ACTIVE);

// Workspace / membership: all collapse to one non-enumerating code
const NA = MCP_DENY.WORKSPACE_NOT_ACCESSIBLE;
expectDeny("missing workspace", (i) => { i.workspace = null; }, NA);
expectDeny("deleted workspace", (i) => { i.workspace.deletedAt = "2026-10-01T00:00:00Z"; }, NA);
expectDeny("workspace deletion state omitted", (i) => { delete i.workspace.deletedAt; }, NA);
expectDeny("workspace deletion state undefined", (i) => { i.workspace.deletedAt = undefined; }, NA);
expectDeny("foreign workspace (no membership)", (i) => { i.membership = null; }, NA);
expectDeny("member role does not exist", (i) => { i.membership.role = "member"; }, NA);
for (const r of [undefined, null, "", 5, "OWNER"]) {
  expectDeny(`membership role ${String(r)}`, (i) => { i.membership = { role: r }; }, NA);
}
expectDeny("membership object without role", (i) => { i.membership = {}; }, NA);
expectDeny("membership undefined", (i) => { i.membership = undefined; }, NA);
expectDeny("legacy owner with memberCount 1", (i) => { i.membership = null; i.workspace.ownerUserId = "usr_1"; i.workspace.memberCount = 1; }, NA);
expectDeny("legacy owner cannot override invalid membership row", (i) => { i.membership = { role: "guest" }; i.workspace.ownerUserId = "usr_1"; i.workspace.memberCount = 0; }, NA);
expectDeny("removed owner (no row, members remain)", (i) => { i.membership = null; i.workspace.ownerUserId = "usr_1"; }, NA);
for (const c of [undefined, null, -1, 1.5, "0", NaN, Infinity]) {
  expectDeny(`memberCount ${String(c)}`, (i) => { i.membership = null; i.workspace.ownerUserId = "usr_1"; i.workspace.memberCount = c; }, NA);
  expectDeny(`memberCount ${String(c)} with membership`, (i) => { i.workspace.memberCount = c; }, NA);
}
expectDeny("zero members, non-owner caller", (i) => { i.membership = null; i.workspace.memberCount = 0; }, NA);
expectDeny("unknown role", (i) => { i.membership.role = "guest"; }, NA);
expectDeny("workspace id mismatch", (i) => { i.workspace.id = "ws_2"; }, NA);
assert.deepEqual(
  run((i) => { i.workspace = null; }),
  run((i) => { i.membership = null; }),
  "foreign and missing workspace denials must be identical",
);
assert.deepEqual(
  run((i) => { i.workspace = null; }),
  run((i) => { i.workspace.deletedAt = 1; }),
);

// Entitlement
for (const e of [null, {}, { mcp: false }, { mcp: "true" }, { mcp: 1 }]) {
  expectDeny(`entitlement ${JSON.stringify(e)}`, (i) => { i.entitlement = e; }, MCP_DENY.ENTITLEMENT_MISSING);
}

// Malformed
for (const bad of [null, undefined, "x", 5, [], true]) {
  const d = evaluateMcpAdmission(bad, NOW);
  assert.equal(d.allowed, false); assert.equal(d.reason, MCP_DENY.MALFORMED_INPUT);
}
for (const w of [undefined, null, "", 5, "a b", "x".repeat(200), {}]) {
  expectDeny(`requested ws ${JSON.stringify(w)}`, (i) => { i.requestedWorkspaceId = w; }, MCP_DENY.MALFORMED_INPUT);
}
expectDeny("bad tokenId", (i) => { i.identity.tokenId = 5; }, MCP_DENY.MALFORMED_INPUT);
expectDeny("array identity", (i) => { i.identity = []; }, MCP_DENY.MALFORMED_INPUT);
assert.equal(evaluateMcpAdmission(base(), NaN).reason, MCP_DENY.MALFORMED_INPUT);

// No mutation, no leakage, frozen output
{
  const input = base();
  const snapshot = JSON.stringify(input);
  const ok = evaluateMcpAdmission(input, NOW);
  const bad = evaluateMcpAdmission({ ...input, entitlement: { mcp: false } }, NOW);
  assert.equal(JSON.stringify(input), snapshot, "input mutated");
  for (const d of [ok, bad]) {
    const s = JSON.stringify(d);
    for (const leak of [SECRET, "a@example.com", "Alice Secret", "usr_other"]) {
      assert.ok(!s.includes(leak), `leaked ${leak}`);
    }
    assert.ok(Object.isFrozen(d));
    assert.deepEqual(Object.keys(d).sort(), ["allowed", "grant", "reason"]);
  }
  assert.ok(Object.isFrozen(ok.grant));
  deepFreeze(input);
  assert.equal(evaluateMcpAdmission(input, NOW).allowed, true, "must work on frozen input");
}
function deepFreeze(o) { Object.values(o).forEach((v) => v && typeof v === "object" && deepFreeze(v)); return Object.freeze(o); }

console.log("PASS validate-mcp-admission: fail-closed MCP-01A admission contract");
