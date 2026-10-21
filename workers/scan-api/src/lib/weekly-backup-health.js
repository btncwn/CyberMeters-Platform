// Weekly off-site exports complement D1 Time Travel; a manual same-provider copy
// cannot satisfy this signal. The event is written only after off-site readback.
import { latestOperationalEvent } from './operational-events.js';
export const WEEKLY_BACKUP_MAX_AGE_MINUTES = 8 * 24 * 60;
export async function weeklyBackupHealth(env, { nowMs = Date.now() } = {}) {
  const row = await latestOperationalEvent(env, 'weekly_backup_completed').catch(() => null);
  const raw = row?.created_at;
  const timestamp = typeof raw === 'string'
    ? Date.parse(raw.includes('T') ? raw : raw.replace(' ', 'T') + 'Z') : NaN;
  const age = Number.isFinite(timestamp) ? (nowMs - timestamp) / 60000 : null;
  const valid = row?.status === 'ok' && /^github-weekly:\d+-\d+$/.test(row?.correlation_id || '') && age !== null && age >= 0;
  return {
    fresh: valid && age <= WEEKLY_BACKUP_MAX_AGE_MINUTES,
    age_minutes: valid ? Math.round(age) : null,
    last_success_at: valid ? new Date(timestamp).toISOString() : null,
  };
}
