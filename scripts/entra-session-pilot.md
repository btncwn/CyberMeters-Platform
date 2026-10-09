# Entra session-revocation pilot

This is a human-operated acceptance tool for the founder-created test account
`cm-identity-test@ttrnn47gmail.onmicrosoft.com`. It uses the provider adapter that
can later be integrated into CyberMeters. **It is not a shipped customer feature.**
No Worker route, UI, SSO permissions, stored connection, database or deployment is
changed by adding these files.

The adapter was exercised with synthetic responses, not a live Entra directory.
Run its offline checks with Node 24:

```sh
node scripts/validate-entra-sessions.js
```

For the real pilot, a separate **single-tenant** Entra app needs Microsoft Graph
application permissions `User.Read.All` (read the selected user's identity and
session baseline) and `User.RevokeSessions.All` (request session revocation), with
administrator consent. **Microsoft grants these permissions across the directory,
not just this test account.** Do not grant them until the administrator explicitly
accepts that scope. This script nevertheless allows only the named test account.
Do not add these permissions to CyberMeters' existing sign-in application.

Use the directory ID and application/client ID from the new app. Keep its client
secret in a password manager; enter it only at the hidden terminal prompt. It is
not a command-line argument, log entry or receipt field. No password-reset,
directory-write, mail, device-management or other permission is requested.

First run the read-only preview:

```sh
node scripts/entra-session-pilot.mjs --tenant TENANT_ID --client APPLICATION_ID
```

On failure, the pilot prints a provider step (`token_exchange`, `user_lookup` or
`session_revocation`) and HTTP status without exposing credentials or response
bodies. Share those diagnostic lines, never the secret. A token-exchange denial
and a Graph user-read denial have different causes; do not repeat the same run or
grant broader permissions without identifying which step failed. Enter the
client secret **Value**, not its Secret ID.

The current user query includes `accountEnabled`. Microsoft's user-read
documentation lists additional permissions for that property; the live preview
must establish whether this selection works with the two approved permissions.
Do not add account-enable/disable permissions just to make the pilot pass.

Keep the test user's existing private-browser session open. After reviewing the
preview and authorizing this target's session revocation, use a new receipt path
in a private folder outside the repository:

```sh
node scripts/entra-session-pilot.mjs --tenant TENANT_ID --client APPLICATION_ID --apply --receipt /absolute/private/entra-test-receipt.json
```

The command shows a fresh preview and requires typing the exact test UPN before
one write. It records a durable attempt before sending the request, refuses an
existing receipt path and never retries a write. If interrupted, or if the
response is uncertain, inspect the saved receipt rather than rerunning.

`provider_accepted` means Microsoft accepted the request, **not** that every
application logged out or that a security finding is resolved. Propagation can
take minutes; previously issued access tokens and application-owned sessions can
remain valid. Independently check the previously signed-in test session and
record whether reauthentication is actually required. Do not delete the user,
disable MFA or change a password to force the expected result.

Before this becomes a customer feature it still needs workspace authorization,
encrypted connection storage, durable preview/action idempotency, UI, focused
independent review and actual-entry/live acceptance. The adapter's in-memory
preview is not a substitute for that product authorization layer.

References: [Graph revoke sessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0),
[read user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0),
[revocation limits](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access).
