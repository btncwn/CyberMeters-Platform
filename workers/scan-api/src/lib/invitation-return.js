// Invitation return path through signup and email verification (P1, 18 Oct 2026).
//
// An invited person who signs up must land back on /invitations/<token> after
// verifying their email. The return path travels inside the verification link
// (no new column), so it survives a different browser or device. It is
// accepted ONLY when it is exactly an invitation path with the real token shape
// (`cmi_` + 64 hex) — never a free-form URL — so it cannot become an open redirect.
export const INVITATION_RETURN_RE = /^\/invitations\/cmi_[0-9a-f]{64}$/;

/** The return path if it is an allow-listed invitation path, else null. */
export function safeInvitationReturn(value) {
  const path = typeof value === "string" ? value.trim() : "";
  return INVITATION_RETURN_RE.test(path) ? path : null;
}

/**
 * Mask an email for a public page: first and last character of the local part,
 * the rest as dots, full domain (c•••••r@gmail.com). The full address is never
 * returned by the public preview.
 */
export function maskEmail(email) {
  const value = String(email || "").trim().toLowerCase();
  const at = value.lastIndexOf("@");
  if (at < 1) return null;
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (!domain) return null;
  const dots = "\u2022".repeat(Math.max(3, local.length - 2));
  const masked = local.length <= 2 ? `${local[0]}${dots}` : `${local[0]}${dots}${local[local.length - 1]}`;
  return `${masked}@${domain}`;
}
