import type { GatewayDatabase } from '../sqlite.js';
import type { CheckpointRecord, DetectedStack, WorkspaceRecord } from '../../types.js';

interface WorkspaceRow {
  slug: string;
  repo_url: string;
  default_branch: string;
  detected_stack_json: string;
  playbook_text: string | null;
  last_synced_at: number | null;
}

interface CheckpointRow {
  checkpoint_id: string;
  workspace_slug: string;
  git_commit_sha: string;
  git_ref: string;
  reason: string;
  created_at: number;
}

function mapWorkspace(row: WorkspaceRow): WorkspaceRecord {
  return {
    slug: row.slug,
    repo_url: row.repo_url,
    default_branch: row.default_branch,
    detected_stack: JSON.parse(row.detected_stack_json) as DetectedStack,
    playbook_text: row.playbook_text,
    last_synced_at: row.last_synced_at,
  };
}

function mapCheckpoint(row: CheckpointRow): CheckpointRecord {
  return {
    checkpoint_id: row.checkpoint_id,
    workspace_slug: row.workspace_slug,
    git_commit_sha: row.git_commit_sha,
    git_ref: row.git_ref,
    reason: row.reason,
    created_at: row.created_at,
  };
}

export class WorkspaceRepository {
  constructor(private readonly db: GatewayDatabase) {}

  upsertWorkspace(input: {
    slug: string;
    repo_url: string;
    default_branch: string;
    detected_stack: DetectedStack;
    playbook_text?: string | null;
    last_synced_at?: number | null;
  }): WorkspaceRecord {
    const lastSyncedAt = input.last_synced_at ?? Date.now();
    const playbookText = input.playbook_text ?? null;
    this.db
      .prepare(
        `INSERT INTO workspaces (slug, repo_url, default_branch, detected_stack_json, playbook_text, last_synced_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(slug) DO UPDATE SET
           repo_url = excluded.repo_url,
           default_branch = excluded.default_branch,
           detected_stack_json = excluded.detected_stack_json,
           playbook_text = excluded.playbook_text,
           last_synced_at = excluded.last_synced_at`,
      )
      .run(
        input.slug,
        input.repo_url,
        input.default_branch,
        JSON.stringify(input.detected_stack),
        playbookText,
        lastSyncedAt,
      );

    return {
      slug: input.slug,
      repo_url: input.repo_url,
      default_branch: input.default_branch,
      detected_stack: input.detected_stack,
      playbook_text: playbookText,
      last_synced_at: lastSyncedAt,
    };
  }

  getWorkspace(slug: string): WorkspaceRecord | null {
    const row = this.db
      .prepare('SELECT * FROM workspaces WHERE slug = ?')
      .get(slug) as WorkspaceRow | undefined;
    return row ? mapWorkspace(row) : null;
  }

  listWorkspaces(): WorkspaceRecord[] {
    const rows = this.db
      .prepare('SELECT * FROM workspaces ORDER BY last_synced_at DESC, slug ASC')
      .all() as WorkspaceRow[];
    return rows.map(mapWorkspace);
  }

  deleteWorkspace(slug: string): boolean {
    const info = this.db.prepare('DELETE FROM workspaces WHERE slug = ?').run(slug);
    return info.changes > 0;
  }

  createCheckpoint(input: {
    checkpoint_id: string;
    workspace_slug: string;
    git_commit_sha: string;
    git_ref: string;
    reason: string;
    created_at?: number;
  }): CheckpointRecord {
    const createdAt = input.created_at ?? Date.now();
    this.db
      .prepare(
        `INSERT INTO checkpoints (checkpoint_id, workspace_slug, git_commit_sha, git_ref, reason, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.checkpoint_id,
        input.workspace_slug,
        input.git_commit_sha,
        input.git_ref,
        input.reason,
        createdAt,
      );

    return {
      checkpoint_id: input.checkpoint_id,
      workspace_slug: input.workspace_slug,
      git_commit_sha: input.git_commit_sha,
      git_ref: input.git_ref,
      reason: input.reason,
      created_at: createdAt,
    };
  }

  getCheckpoint(checkpointId: string): CheckpointRecord | null {
    const row = this.db
      .prepare('SELECT * FROM checkpoints WHERE checkpoint_id = ?')
      .get(checkpointId) as CheckpointRow | undefined;
    return row ? mapCheckpoint(row) : null;
  }

  listCheckpoints(workspaceSlug: string, limit = 50): CheckpointRecord[] {
    const rows = this.db
      .prepare(
        'SELECT * FROM checkpoints WHERE workspace_slug = ? ORDER BY created_at DESC LIMIT ?',
      )
      .all(workspaceSlug, limit) as CheckpointRow[];
    return rows.map(mapCheckpoint);
  }
}
