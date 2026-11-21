import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

export type GatewayDatabase = Database.Database;

export interface Migration {
  version: number;
  name: string;
  up(db: GatewayDatabase): void;
}

const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'initial_schema',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS oauth_clients (
          client_id TEXT PRIMARY KEY,
          client_secret_hash TEXT,
          client_name TEXT NOT NULL,
          redirect_uris_json TEXT NOT NULL,
          is_static INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_auth_requests (
          auth_req_id TEXT PRIMARY KEY,
          client_id TEXT NOT NULL,
          redirect_uri TEXT NOT NULL,
          state TEXT,
          code_challenge TEXT NOT NULL,
          code_challenge_method TEXT NOT NULL,
          scope TEXT NOT NULL,
          resource TEXT,
          csrf_token TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          used INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS oauth_codes (
          code TEXT PRIMARY KEY,
          client_id TEXT NOT NULL,
          redirect_uri TEXT NOT NULL,
          code_challenge TEXT NOT NULL,
          scope TEXT NOT NULL,
          resource TEXT,
          expires_at INTEGER NOT NULL,
          used INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS oauth_tokens (
          token_hash TEXT PRIMARY KEY,
          token_type TEXT NOT NULL,
          client_id TEXT NOT NULL,
          scope TEXT NOT NULL,
          resource TEXT,
          token_family_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          grace_expires_at INTEGER,
          revoked INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS workspaces (
          slug TEXT PRIMARY KEY,
          repo_url TEXT NOT NULL,
          default_branch TEXT NOT NULL,
          detected_stack_json TEXT NOT NULL,
          playbook_text TEXT,
          last_synced_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS checkpoints (
          checkpoint_id TEXT PRIMARY KEY,
          workspace_slug TEXT NOT NULL,
          git_commit_sha TEXT NOT NULL,
          git_ref TEXT NOT NULL,
          reason TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          FOREIGN KEY (workspace_slug) REFERENCES workspaces(slug) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS jobs (
          job_id TEXT PRIMARY KEY,
          workspace_slug TEXT NOT NULL,
          runner_type TEXT NOT NULL,
          status TEXT NOT NULL,
          command_or_objective TEXT NOT NULL,
          codex_thread_id TEXT,
          checkpoint_id TEXT,
          events_json TEXT NOT NULL DEFAULT '[]',
          token_usage_json TEXT,
          final_report_text TEXT,
          error_message TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mutation_plans (
          plan_id TEXT PRIMARY KEY,
          target_service TEXT NOT NULL,
          summary_diff_text TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          rollback_payload_json TEXT,
          status TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          executed_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          target TEXT NOT NULL,
          status TEXT NOT NULL,
          details_json TEXT NOT NULL DEFAULT '{}',
          created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_oauth_auth_req_expires ON oauth_auth_requests(expires_at);
        CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at);
        CREATE INDEX IF NOT EXISTS idx_oauth_tokens_family ON oauth_tokens(token_family_id);
        CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client ON oauth_tokens(client_id, token_type);
        CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires ON oauth_tokens(expires_at);
        CREATE INDEX IF NOT EXISTS idx_checkpoints_workspace ON checkpoints(workspace_slug, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_jobs_workspace_status ON jobs(workspace_slug, status, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_jobs_updated_at ON jobs(updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_mutation_plans_status_exp ON mutation_plans(status, expires_at);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, created_at DESC);
      `);
    },
  },
  {
    version: 2,
    name: 'upstream_oauth_states',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS oauth_upstream_states (
          state TEXT PRIMARY KEY,
          provider TEXT NOT NULL,
          purpose TEXT NOT NULL,
          auth_req_id TEXT,
          code_verifier TEXT NOT NULL,
          binding_hash TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          used INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_oauth_upstream_states_expires ON oauth_upstream_states(expires_at);
      `);
    },
  },
  {
    version: 3,
    name: 'workspace_memories',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS workspace_memories (
          memory_id TEXT PRIMARY KEY,
          workspace_slug TEXT NOT NULL,
          category TEXT NOT NULL,
          key TEXT NOT NULL,
          content TEXT NOT NULL,
          pinned INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          UNIQUE(workspace_slug, category, key)
        );

        CREATE INDEX IF NOT EXISTS idx_workspace_memories_lookup
          ON workspace_memories (workspace_slug, pinned DESC, updated_at DESC);
      `);
    },
  },
  {
    version: 4,
    name: 'mcp_usage_events',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS mcp_usage_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          tool_name TEXT NOT NULL,
          client_id TEXT,
          status TEXT NOT NULL,
          input_bytes INTEGER NOT NULL,
          output_bytes INTEGER NOT NULL,
          est_input_tokens INTEGER NOT NULL,
          est_output_tokens INTEGER NOT NULL,
          duration_ms INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_mcp_usage_events_created
          ON mcp_usage_events (created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_mcp_usage_events_tool
          ON mcp_usage_events (tool_name, created_at DESC);
      `);
    },
  },
];

/**
 * Applies all pending schema migrations idempotently inside transactions.
 */
export function runMigrations(db: GatewayDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at INTEGER NOT NULL
    );
  `);

  const appliedStmt = db.prepare('SELECT version FROM schema_migrations');
  const appliedVersions = new Set<number>(
    (appliedStmt.all() as Array<{ version: number }>).map((row) => row.version),
  );

  const insertMigration = db.prepare(
    'INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)',
  );

  for (const migration of MIGRATIONS) {
    if (appliedVersions.has(migration.version)) continue;

    const apply = db.transaction(() => {
      migration.up(db);
      insertMigration.run(migration.version, migration.name, Date.now());
    });
    apply();
  }
}

/**
 * Opens (or creates) the SQLite database with WAL mode, foreign keys, and migrations applied.
 * Pass ":memory:" for isolated in-memory test databases.
 */
export function openDatabase(databasePath: string): GatewayDatabase {
  if (databasePath !== ':memory:') {
    const dir = path.dirname(databasePath);
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(databasePath);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');

  runMigrations(db);
  return db;
}
