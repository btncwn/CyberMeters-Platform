// Real migrated SQLite and production auth routes; synthetic identities only.
import { buildDb } from '../security/lib/worker-harness.js';

export function setup() {
  const db = buildDb();
  db.exec('PRAGMA foreign_keys=ON');
  let fault = null;
  const statement = (sql, args = []) => ({
    sql, args,
    bind: (...bound) => statement(sql, bound),
    first: async () => {
      if (fault?.(sql)) throw new Error('storage');
      return db.prepare(sql).get(...args) || null;
    },
    run: async () => {
      if (fault?.(sql)) throw new Error('storage');
      return { meta: { changes: db.prepare(sql).run(...args).changes } };
    },
  });
  for (const user of ['owner', 'other', 'member']) {
    db.prepare('INSERT INTO users(id,email,email_verified) VALUES(?,?,1)').run(user, `${user}@example.com`);
  }
  const env = {
    cybermeters_db: {
      prepare: sql => statement(sql),
      // Execute synchronously within one SQLite transaction to model D1 batch
      // isolation, including simultaneous reset requests against the same token.
      batch: async statements => {
        db.exec('BEGIN');
        try {
          const results = statements.map(({ sql, args }) => {
            if (fault?.(sql)) throw new Error('storage');
            return { meta: { changes: db.prepare(sql).run(...args).changes } };
          });
          db.exec('COMMIT');
          return results;
        } catch (error) { db.exec('ROLLBACK'); throw error; }
      },
    },
  };
  const context = (route, { method = 'GET', body } = {}) => ({
    env, url: new URL(`https://test.invalid${route}`),
    request: new Request(`https://test.invalid${route}`, { method, ...(body ? { body: JSON.stringify(body) } : {}) }),
    requireAuth: async () => null,
    consumeApiRateLimit: async () => null,
    rateLimitScopeId: async (_, ip) => ip,
    json: (body, status = 200) => Response.json(body, { status }),
    serverError: () => Response.json({ error: 'Unavailable' }, { status: 500 }),
  });
  return { db, env, context, setFault: value => { fault = value; } };
}
