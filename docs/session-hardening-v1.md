# CyberMeters Session Hardening — Root Cause Analysis v1

**Sprint 10A — Phase 5**
**Date:** June 2026
**Status:** Implemented

---

## Problem Statement

Users could end up with a stale `cybermeters_workspace_id` in localStorage — pointing to a workspace that no longer exists or to one they no longer have access to. This caused:

- Silent 404 / 403 failures on workspace-scoped API calls
- Blank pages or stuck loading states with no user-visible error
- New Microsoft SSO users landing on `/dashboard` with no workspace at all
- New local-auth users who registered and verified email but had no workspace created for them

---

## Root Cause

`useWorkspace.js` read exclusively from localStorage:

```js
const [wsId, setWsId] = useState(() => localStorage.getItem('cybermeters_workspace_id'))
```

And a 1-second polling interval synced state to localStorage, but never validated the stored ID against the server. localStorage was treated as the *source of truth* rather than a *cache hint*.

### Failure modes

| Scenario | Before fix | After fix |
|---|---|---|
| New local-auth user, no workspace | Blank workspace selector; API calls fail | Auto-bootstrap creates default workspace |
| New Microsoft SSO user | Lands on `/dashboard` with no workspace | `useWorkspace` bootstraps on mount |
| Workspace deleted by admin | Stale ID silently causes 403s forever | Falls back to `default_workspace_id` from server |
| User's membership revoked | Same — silent 403s | Revalidated on every auth'd mount |
| Name change server-side | Stale display name in UI forever | Name refreshed from server list |

---

## Fix: `hooks/useWorkspace.js`

On mount (when `cybermeters_auth_token` is present in localStorage):

1. `GET /api/workspaces` — fetch the real accessible workspace list.
2. If list is empty → `POST /api/account/bootstrap` to auto-create a default workspace.
3. Validate stored `cybermeters_workspace_id` against the list.
   - If valid → confirm name is current, update if stale.
   - If stale/absent → use `default_workspace_id` from server, or fall back to first owner workspace, then first in list.
4. Write validated ID + name back to localStorage.
5. Set `loading = false`.

Network failure is non-fatal: existing localStorage values are preserved.

The hook now exposes `{ wsId, wsName, workspaces, loading, setWorkspace }`. The new `loading` flag lets consuming pages show a spinner while the initial validation is in progress rather than immediately rendering with a possibly-invalid workspace context.

---

## Fix: `POST /api/account/bootstrap` (Worker)

Added idempotent endpoint that:

- Returns the user's first (oldest) workspace if any exist — no-op for existing users.
- Creates a workspace named `{Name}'s Workspace` (or `{brand} Workspace` from email domain) and inserts an `owner` row in `workspace_members`.
- Emits a `workspace_bootstrapped` audit event.
- Returns `{ workspace: { id, name, created_at }, created: bool }`.

Blocked for API token sessions (session auth only). Returns 201 on creation, 200 on existing.

---

## Fix: `GET /api/workspaces` (Worker)

Updated response to include:

- `default_workspace_id` — earliest-created workspace where the user has `owner` role, falling back to first accessible workspace.
- `role` per workspace entry — via `LEFT JOIN workspace_members`.

This allows `useWorkspace.js` to pick the correct fallback without a second round-trip.

---

## Microsoft SSO

`MicrosoftCallbackPage.jsx` was not modified. The callback calls `login()` and immediately navigates to `/dashboard`. Because `useWorkspace.js` now runs server validation + bootstrap on every authenticated mount, new Microsoft SSO users who arrive at the dashboard with no workspace will have one auto-created within the first render cycle while `loading = true`.

Microsoft OAuth users have `email_verified = 1` set at registration (auto-verified), so they bypass the email verification gate and proceed directly to onboarding.

---

## What Was Not Changed

- MicrosoftCallbackPage.jsx — not needed; bootstrap handled transparently by `useWorkspace.js`
- AuthContext.jsx — unchanged
- localStorage key names — unchanged (`cybermeters_workspace_id`, `cybermeters_workspace_name`)
- Existing consumers of `useWorkspace()` that only destructure `{ wsId, wsName }` — backward compatible; new fields are additive

---

## Migration Notes

No database schema changes. No new migration required.

`POST /api/account/bootstrap` uses the existing `workspaces` and `workspace_members` tables. Both exist from migrations `003-workspaces.sql` and `015-rbac.sql`.

---

## Suggested Commit

```
feat(10A): session hardening — server-authoritative workspace validation & auto-bootstrap

- useWorkspace.js: fetch /api/workspaces on mount, validate stored ID,
  auto-bootstrap empty users, fall back to server default_workspace_id
- Worker: POST /api/account/bootstrap — idempotent default workspace creation
- Worker: GET /api/workspaces — add default_workspace_id + role per entry
- api.js: add bootstrapWorkspace() method
- OnboardingPage.jsx: add CopyButton for TXT value in Step 3

Resolves: stale localStorage workspace ID causing silent 403s
Resolves: new users landing on /dashboard with no workspace
Resolves: Microsoft SSO users with no workspace auto-creation
```
