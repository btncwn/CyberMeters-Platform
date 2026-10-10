import { TRIAL_SPEC } from "./pricing-registry.js";

export const REPORT_RESERVATION_MINUTES = 30;

export function trialDay(now = new Date()) {
  const start = now.toISOString().slice(0, 10);
  const reset = new Date(`${start}T00:00:00.000Z`);
  reset.setUTCDate(reset.getUTCDate() + 1);
  return { start, end: reset.toISOString().slice(0, 10), reset_at: reset.toISOString() };
}

// Use the date prefix bounds: both SQLite's "YYYY-MM-DD HH:mm:ss" and ISO
// timestamps sort within the same UTC day. Include deleted history so deleting
// an artifact/workspace cannot replenish an account's allowance.
export function trialUsageSql(resource, ownerId, now = new Date()) {
  // Admission uses SQLite's clock in the INSERT itself: a request queued over
  // midnight must check and consume the same day's allowance.
  const day = now ? trialDay(now) : null;
  const start = day ? "?" : "date('now')";
  const end = day ? "?" : "date('now', '+1 day')";
  const bounds = day ? [day.start, day.end] : [];
  if (resource === "scans") return {
    sql: `((SELECT COUNT(*) FROM scans s JOIN workspaces w ON w.id = s.workspace_id
      WHERE w.owner_user_id = ? AND s.created_at >= ${start} AND s.created_at < ${end} AND s.status != 'failed')
      + (SELECT COUNT(*) FROM network_scans n JOIN workspaces w ON w.id = n.workspace_id
      WHERE w.owner_user_id = ? AND n.created_at >= ${start} AND n.created_at < ${end} AND n.status != 'failed'))`,
    args: [ownerId, ...bounds, ownerId, ...bounds],
  };
  if (resource !== "reports") throw new Error("invalid_trial_resource");
  const freshAfter = now ? new Date(now.getTime() - REPORT_RESERVATION_MINUTES * 60_000).toISOString() : null;
  return {
    sql: `(SELECT COUNT(*) FROM workspace_reports r JOIN workspaces w ON w.id = r.workspace_id
      WHERE w.owner_user_id = ? AND r.created_at >= ${start} AND r.created_at < ${end}
      AND (r.status = 'completed' OR (r.status = 'pending' AND julianday(r.created_at) >= ${now ? "julianday(?)" : `julianday('now', '-${REPORT_RESERVATION_MINUTES} minutes')`})))`,
    args: [ownerId, ...bounds, ...(now ? [freshAfter] : [])],
  };
}

export async function trialUsage(env, resource, ownerId, now = new Date()) {
  const query = trialUsageSql(resource, ownerId, now);
  const row = await env.cybermeters_db.prepare(`SELECT ${query.sql} AS cnt`).bind(...query.args).first();
  if (!Number.isSafeInteger(row?.cnt) || row.cnt < 0) throw new Error("trial_usage_unavailable");
  return row.cnt;
}

export function trialQuotaError(resource, used, now = new Date()) {
  const limit = TRIAL_SPEC[`${resource}_per_day`];
  const noun = resource === "scans" ? "scans" : "new PDFs";
  return { status: 403, body: {
    error: "plan_limit_exceeded", reason: "trial_daily_allowance", title: "Today's trial allowance is used",
    resource: `${resource}_per_day`, limit, usage: used, remaining: Math.max(0, limit - used),
    reset_at: trialDay(now).reset_at,
    upgrade_message: `You have used today's ${noun}. More are available at 00:00 UTC.`,
  } };
}

export function inactivePlanError(state) {
  return { status: 403, body: {
    error: "plan_limit_exceeded", reason: state.trial_expired ? "trial_expired" : "plan_inactive",
    title: state.trial_expired ? "Your trial has ended" : "An active trial or plan is needed",
    upgrade_message: state.trial_expired
      ? "Your 14-day trial has ended. Your saved results and PDFs remain available. Choose a plan to start new scans or generate new reports."
      : "Start your trial or choose a plan to run scans and generate reports. Your saved results and PDFs remain available.",
  } };
}

export async function getTrialAllowance(env, ownerId, state, now = new Date()) {
  if (!state.is_trial) return { active: false, expired: !!state.trial_expired };
  const [scans, reports] = await Promise.all([trialUsage(env, "scans", ownerId, now), trialUsage(env, "reports", ownerId, now)]);
  return { active: true, expired: false, reset_at: trialDay(now).reset_at, reset_timezone: "UTC",
    scans: { used: scans, limit: TRIAL_SPEC.scans_per_day, remaining: Math.max(0, TRIAL_SPEC.scans_per_day - scans) },
    reports: { used: reports, limit: TRIAL_SPEC.reports_per_day, remaining: Math.max(0, TRIAL_SPEC.reports_per_day - reports) },
  };
}
