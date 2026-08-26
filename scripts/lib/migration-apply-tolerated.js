// F-025 / F-035 (corrective, statement granularity) — migration/schema apply errors are
// TERMINAL, and tolerance is bound to the EXACT MIGRATION FILE BYTES *and* the EXACT FAILING
// STATEMENT (not merely file+message). R1 (CORRECTIVE_REQUIRED) proved the file+message form
// still false-greened: db.exec() runs a whole file and STOPS at the first error, so a
// tolerated FIRST error silently skipped every later statement in that file (e.g. migration
// 045's second `ADD contact_name` never ran; migration 046's index DROP/CREATE never ran →
// idx_customer_profiles_owner was unique=0/partial=0). The fix applies each statement
// individually (see splitStatements) so the remainder always runs, and tolerates ONLY the
// enumerated (file-bytes, statement, message) occurrences; anything else is TERMINAL.
//
// PROVENANCE (measured on base 47d9bb39, tree 6b408497, node:sqlite, schema.sql-first,
// statement-level): the 6 tolerated files' erroring statements are the 028/029 migration-ORDER
// artifact (they reference `subscriptions`, created later by migration 047 and absent from
// schema.sql — these ALTER/UPDATE statements are historically dead) and the 045/046/106/107
// duplicate-column re-adds already carried by the consolidated schema.sql. If a tolerated
// file's BYTES change, its fileSha256 no longer matches → NONE of its statements are tolerated
// → terminal, forcing a fresh measurement. Re-measure and regenerate this list ONLY then.

// Single-pass lexical statement splitter for SQLite migration files. The prior
// regex/BEGIN-END depth counter was not lexically aware (R1 P1-R1-01): it stripped
// comments without context and counted EVERY BEGIN/END/';', so it shattered a valid
// CREATE TRIGGER whose body contains `CASE ... END` (the CASE's END wrongly closed
// the trigger, and the following inner ';' ended the fragment) and split on a ';'
// inside a quoted literal. This scanner treats ';', comments and the
// BEGIN/CASE/END keywords as significant ONLY in NORMAL lexical state, tracks the
// trigger body's block depth (the body BEGIN and each nested CASE open a level;
// each END closes one) DISTINCTLY so an expression `END` never terminates the
// trigger, and keeps a trigger body's inner ';' inside its statement. A statement
// terminates only on a NORMAL ';' at block depth 0.
//
// Defends, with named right-reason controls in the closure validator, against:
//   CASE_END_AS_TRIGGER_END · TRIGGER_INNER_SEMICOLON_SPLIT ·
//   QUOTED_SEMICOLON_SPLIT · QUOTED_COMMENT_STRIP.
export function splitStatements(sql) {
  const s = String(sql || "");
  const n = s.length;
  const out = [];
  let buf = "";           // current statement text: comments stripped, quoted runs verbatim
  let word = "";          // current NORMAL-state identifier/keyword run
  let depth = 0;          // trigger-body block depth (trigger BEGIN + nested CASE open; END closes)
  let isTrigger = false;  // the current statement is a CREATE ... TRIGGER
  let sawCreate = false;  // CREATE seen at the head of the current statement

  const applyKeyword = () => {
    if (!word) return;
    switch (word.toUpperCase()) {
      case "CREATE": sawCreate = true; break;
      case "TEMP": case "TEMPORARY": break;                                 // stay in the CREATE ... TRIGGER header
      case "TRIGGER": if (sawCreate) isTrigger = true; sawCreate = false; break;
      case "BEGIN": if (isTrigger && depth === 0) depth = 1; sawCreate = false; break; // trigger body opens
      case "CASE": if (isTrigger && depth >= 1) depth += 1; sawCreate = false; break;  // nested CASE ... END
      case "END": if (isTrigger && depth >= 1) depth -= 1; sawCreate = false; break;   // closes a CASE or the body
      default: sawCreate = false; break;
    }
    word = "";
  };
  const resetStatement = () => { depth = 0; isTrigger = false; sawCreate = false; word = ""; };

  let i = 0;
  while (i < n) {
    const c = s[i];
    const c2 = i + 1 < n ? s[i + 1] : "";

    // Line comment — NORMAL only. Skip to end of line; the '\n' is handled next iteration.
    if (c === "-" && c2 === "-") { applyKeyword(); i += 2; while (i < n && s[i] !== "\n") i += 1; continue; }
    // Block comment — NORMAL only. Skip to '*/'; acts as a token separator.
    if (c === "/" && c2 === "*") { applyKeyword(); i += 2; while (i < n && !(s[i] === "*" && s[i + 1] === "/")) i += 1; i += 2; buf += " "; continue; }
    // Quoted literal/identifier: ' " ` end on a doubling-aware closer; [ ... ] ends at the first ].
    // Everything inside is verbatim — a ';', comment marker or keyword inside is NOT interpreted.
    if (c === "'" || c === '"' || c === "`" || c === "[") {
      applyKeyword();
      const close = c === "[" ? "]" : c;
      const doubles = c !== "[";                                  // '' "" `` are escapes; ]] is not
      buf += c; i += 1;
      while (i < n) {
        const d = s[i];
        if (d === close) {
          if (doubles && s[i + 1] === close) { buf += d + close; i += 2; continue; }
          buf += d; i += 1; break;
        }
        buf += d; i += 1;
      }
      continue;
    }
    // Identifier/keyword characters accumulate for keyword detection.
    if (/[A-Za-z0-9_]/.test(c)) { word += c; buf += c; i += 1; continue; }

    // Any other char is a token boundary — resolve the pending keyword first.
    applyKeyword();
    if (c === ";") {
      if (depth === 0) { const st = buf.trim(); if (st) out.push(st); buf = ""; resetStatement(); }
      else { buf += c; }                                          // inner ';' inside a trigger body
      i += 1; continue;
    }
    buf += c; i += 1;
  }
  applyKeyword();
  const last = buf.trim();
  if (last) out.push(last);
  return out;
}

export function normalizeSql(s) { return String(s || "").replace(/\s+/g, " ").trim(); }

export const TOLERATED_MIGRATION_STATEMENTS = Object.freeze([
  { file: "028-stripe-billing.sql", fileSha256: "32979abb32ffe6d476a330c2f81c3d250946eb6065dc452750c52f71e324fa4e", statements: [
    { sql: "ALTER TABLE subscriptions ADD COLUMN stripe_customer_id TEXT", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN stripe_subscription_id TEXT", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN stripe_price_id TEXT", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN billing_interval TEXT DEFAULT 'monthly'", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN cancel_at_period_end INTEGER DEFAULT 0", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN cancelled_at TEXT", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN payment_failed_at TEXT", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN payment_retry_count INTEGER DEFAULT 0", message: "no such table: subscriptions" },
    { sql: "CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer ON subscriptions (stripe_customer_id) WHERE stripe_customer_id IS NOT NULL", message: "no such table: main.subscriptions" },
    { sql: "CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_subscription ON subscriptions (stripe_subscription_id) WHERE stripe_subscription_id IS NOT NULL", message: "no such table: main.subscriptions" },
  ] },
  { file: "029-billing-schema-alignment.sql", fileSha256: "d05dee92d5c07bb3585fc2eb033be104d6c745312e20d38478e2f919d370c455", statements: [
    { sql: "ALTER TABLE subscriptions ADD COLUMN owner_user_id TEXT", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN subscription_status TEXT", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN current_period_end TEXT", message: "no such table: subscriptions" },
    { sql: "ALTER TABLE subscriptions ADD COLUMN updated_at TEXT", message: "no such table: subscriptions" },
    { sql: "UPDATE subscriptions SET owner_user_id = ( SELECT workspaces.owner_user_id FROM workspaces WHERE workspaces.id = subscriptions.workspace_id ) WHERE owner_user_id IS NULL AND workspace_id IS NOT NULL", message: "no such table: subscriptions" },
    { sql: "UPDATE subscriptions SET subscription_status = status WHERE subscription_status IS NULL AND status IS NOT NULL", message: "no such table: subscriptions" },
    { sql: "UPDATE subscriptions SET current_period_end = expires_at WHERE current_period_end IS NULL AND expires_at IS NOT NULL", message: "no such table: subscriptions" },
    { sql: "UPDATE subscriptions SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL", message: "no such table: subscriptions" },
  ] },
  { file: "045-company-profile-columns.sql", fileSha256: "4a5fe0f1c90d32a39cc59fec59c0dce3de3175541b3b57686b7b1a2f8e9eb935", statements: [
    { sql: "ALTER TABLE customer_profiles ADD COLUMN contact_email TEXT", message: "duplicate column name: contact_email" },
    { sql: "ALTER TABLE customer_profiles ADD COLUMN contact_name TEXT", message: "duplicate column name: contact_name" },
  ] },
  { file: "046-customer-profile-owner-user-id.sql", fileSha256: "526ae8287521dc9c63cf9d883dd5bd8fcb8df28d0103eae3ce1686115727b8d4", statements: [
    { sql: "ALTER TABLE customer_profiles ADD COLUMN owner_user_id TEXT", message: "duplicate column name: owner_user_id" },
  ] },
  { file: "106-scheduled-asset-change-projection.sql", fileSha256: "1bb5157157bed645c6a3f327c3f47af1b02c54950423f4406dfa4c2fe7766e81", statements: [
    { sql: "ALTER TABLE scheduled_scans ADD COLUMN asset_change_projection_json TEXT", message: "duplicate column name: asset_change_projection_json" },
  ] },
  { file: "107-finding-canonical-identity.sql", fileSha256: "48b929eb87bde88066b8461ff51e005ce2c6ec470ef5ca4454ca63f974b45c82", statements: [
    { sql: "ALTER TABLE findings ADD COLUMN finding_slug TEXT", message: "duplicate column name: finding_slug" },
  ] }
,
]);

// A statement error is tolerated ONLY when the migration file's CURRENT bytes match the frozen
// fileSha256 AND the exact failing statement (normalized) + message are enumerated for it.
export function isToleratedStatement(file, fileSha256, statementSql, message) {
  const entry = TOLERATED_MIGRATION_STATEMENTS.find((t) => t.file === file && t.fileSha256 === fileSha256);
  if (!entry) return false;
  const nsql = normalizeSql(statementSql);
  const m = String(message || "").trim();
  return entry.statements.some((s) => normalizeSql(s.sql) === nsql && s.message === m);
}
