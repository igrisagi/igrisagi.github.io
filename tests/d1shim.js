// Minimal D1-compatible wrapper over node:sqlite so Pages Functions can be
// tested locally against real SQL. Implements prepare().bind().run/all/first.
import { DatabaseSync } from 'node:sqlite';

export function createD1() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  return {
    _db: db,
    prepare(sql) {
      let args = [];
      const stmt = db.prepare(sql);
      const api = {
        bind(...a) { args = a; return api; },
        async run() {
          const r = stmt.run(...args);
          return { meta: { changes: r.changes, last_row_id: r.lastInsertRowid } };
        },
        async all() { return { results: stmt.all(...args) }; },
        async first() { return stmt.get(...args) ?? null; }
      };
      return api;
    }
  };
}

export function migrate(db, sql) {
  db._db.exec(sql);
}
