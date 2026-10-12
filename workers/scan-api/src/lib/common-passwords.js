// Common-password screening for new passwords (signup and password reset).
//
// The list ships with the Worker (common-passwords-data.js); no password, hash
// or prefix leaves the server and no outside service is called. The check says
// only that a password is on this list of commonly used passwords — it is not
// a search of every data breach.
//
// The list is verified (entry count and SHA-256) the first time it is used in
// an isolate. A damaged or truncated list fails closed: new passwords are
// refused with a temporary error rather than accepted unchecked.
import { COMMON_PASSWORD_LIST } from "./common-passwords-data.js";

export function normalisePasswordForList(password) {
  return String(password).normalize("NFKC").toLowerCase();
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Build a checker for one list. Returns 'common', 'not_listed', or
// 'unavailable' when the list does not verify.
export function createCommonPasswordChecker(list) {
  let loaded = null;
  const load = async () => {
    try {
      const text = typeof list?.entries === "string" ? list.entries : "";
      const entries = text ? text.split("\n") : [];
      const intact = entries.length > 0 &&
        entries.length === list.count &&
        (await sha256Hex(text)) === list.sha256;
      return intact ? new Set(entries) : null;
    } catch {
      return null;
    }
  };
  return async function check(password) {
    loaded ??= load();
    const set = await loaded;
    if (!set) return "unavailable";
    return set.has(normalisePasswordForList(password)) ? "common" : "not_listed";
  };
}

const checkBundled = createCommonPasswordChecker(COMMON_PASSWORD_LIST);

export async function newPasswordRejection(password, { check = checkBundled } = {}) {
  const result = await check(password);
  if (result === "common") return {
    status: 400,
    body: { code: "password_too_common", error: "This password is on a list of commonly used passwords. Choose a different password." },
  };
  if (result !== "not_listed") return {
    status: 503,
    body: { code: "password_check_unavailable", error: "The password check is temporarily unavailable. Please try again." },
  };
  return null;
}
