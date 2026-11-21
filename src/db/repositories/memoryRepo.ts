import { randomUUID } from 'node:crypto';
import type { GatewayDatabase } from '../sqlite.js';
import type { MemoryCategory, WorkspaceMemoryRecord } from '../../types.js';

export const MAX_MEMORIES_PER_WORKSPACE = 100;
export const MAX_MEMORY_CONTENT_BYTES = 8192;
export const MEMORY_CATEGORIES: readonly MemoryCategory[] = [
  'task_state',
  'decision',
  'pitfall',
  'preference',
  'note',
] as const;

const WORKSPACE_SLUG_REGEX = /^[a-zA-Z0-9._-]{1,128}$/;
const MEMORY_KEY_REGEX = /^[a-zA-Z0-9._:/-]{1,80}$/;

interface WorkspaceMemoryRow {
  memory_id: string;
  workspace_slug: string;
  category: string;
  key: string;
  content: string;
  pinned: number;
  created_at: number;
  updated_at: number;
}

function mapMemory(row: WorkspaceMemoryRow): WorkspaceMemoryRecord {
  return {
    memory_id: row.memory_id,
    workspace_slug: row.workspace_slug,
    category: row.category as MemoryCategory,
    key: row.key,
    content: row.content,
    pinned: row.pinned === 1,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function assertValidWorkspaceSlug(slug: string): void {
  if (!WORKSPACE_SLUG_REGEX.test(slug) || slug === '.' || slug === '..') {
    throw new Error(`Invalid workspace slug "${slug}"`);
  }
}

function assertValidCategory(category: string): asserts category is MemoryCategory {
  if (!MEMORY_CATEGORIES.includes(category as MemoryCategory)) {
    throw new Error(
      `Invalid memory category "${category}". Expected one of: ${MEMORY_CATEGORIES.join(', ')}`,
    );
  }
}

function assertValidKey(key: string): void {
  if (!MEMORY_KEY_REGEX.test(key)) {
    throw new Error(
      `Invalid memory key "${key}". Must match ^[a-zA-Z0-9._:/-]{1,80}$`,
    );
  }
}

export interface UpsertMemoryInput {
  workspaceSlug: string;
  category: MemoryCategory;
  key: string;
  content: string;
  pinned?: boolean;
  now?: number;
}

export interface ListMemoriesFilter {
  workspaceSlug?: string;
  category?: MemoryCategory;
  pinnedOnly?: boolean;
  limit?: number;
}

export class MemoryRepository {
  constructor(private readonly db: GatewayDatabase) {}

  upsertMemory(input: UpsertMemoryInput): WorkspaceMemoryRecord {
    assertValidWorkspaceSlug(input.workspaceSlug);
    assertValidCategory(input.category);
    assertValidKey(input.key);

    if (typeof input.content !== 'string' || input.content.trim().length === 0) {
      throw new Error('Memory content must be a non-empty string');
    }
    const contentBytes = Buffer.byteLength(input.content, 'utf8');
    if (contentBytes > MAX_MEMORY_CONTENT_BYTES) {
      throw new Error(
        `Memory content exceeds max size (${contentBytes} > ${MAX_MEMORY_CONTENT_BYTES} bytes)`,
      );
    }

    const now = input.now ?? Date.now();

    return this.db.transaction((): WorkspaceMemoryRecord => {
      const existing = this.db
        .prepare(
          'SELECT * FROM workspace_memories WHERE workspace_slug = ? AND category = ? AND key = ?',
        )
        .get(input.workspaceSlug, input.category, input.key) as WorkspaceMemoryRow | undefined;

      if (existing) {
        const nextPinned = input.pinned !== undefined ? (input.pinned ? 1 : 0) : existing.pinned;
        this.db
          .prepare(
            `UPDATE workspace_memories
             SET content = ?, pinned = ?, updated_at = ?
             WHERE memory_id = ?`,
          )
          .run(input.content, nextPinned, now, existing.memory_id);

        return mapMemory({
          ...existing,
          content: input.content,
          pinned: nextPinned,
          updated_at: now,
        });
      }

      const countRow = this.db
        .prepare('SELECT COUNT(*) AS cnt FROM workspace_memories WHERE workspace_slug = ?')
        .get(input.workspaceSlug) as { cnt: number };
      if (Number(countRow.cnt) >= MAX_MEMORIES_PER_WORKSPACE) {
        throw new Error(
          `Workspace "${input.workspaceSlug}" reached max memory limit (${MAX_MEMORIES_PER_WORKSPACE})`,
        );
      }

      const memoryId = `mem_${randomUUID()}`;
      const pinnedInt = input.pinned ? 1 : 0;

      this.db
        .prepare(
          `INSERT INTO workspace_memories
           (memory_id, workspace_slug, category, key, content, pinned, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          memoryId,
          input.workspaceSlug,
          input.category,
          input.key,
          input.content,
          pinnedInt,
          now,
          now,
        );

      return {
        memory_id: memoryId,
        workspace_slug: input.workspaceSlug,
        category: input.category,
        key: input.key,
        content: input.content,
        pinned: pinnedInt === 1,
        created_at: now,
        updated_at: now,
      };
    })();
  }

  listMemories(filter: ListMemoriesFilter = {}): WorkspaceMemoryRecord[] {
    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (filter.workspaceSlug) {
      assertValidWorkspaceSlug(filter.workspaceSlug);
      clauses.push('workspace_slug = ?');
      params.push(filter.workspaceSlug);
    }
    if (filter.category) {
      assertValidCategory(filter.category);
      clauses.push('category = ?');
      params.push(filter.category);
    }
    if (filter.pinnedOnly) {
      clauses.push('pinned = 1');
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Math.max(1, Math.min(200, filter.limit ?? 100));
    params.push(limit);

    const rows = this.db
      .prepare(
        `SELECT * FROM workspace_memories ${where} ORDER BY pinned DESC, updated_at DESC LIMIT ?`,
      )
      .all(...params) as WorkspaceMemoryRow[];
    return rows.map(mapMemory);
  }

  getMemoryById(memoryId: string): WorkspaceMemoryRecord | null {
    const row = this.db
      .prepare('SELECT * FROM workspace_memories WHERE memory_id = ?')
      .get(memoryId) as WorkspaceMemoryRow | undefined;
    return row ? mapMemory(row) : null;
  }

  deleteMemory(workspaceSlug: string, category: MemoryCategory, key: string): boolean {
    assertValidWorkspaceSlug(workspaceSlug);
    assertValidCategory(category);
    assertValidKey(key);

    const info = this.db
      .prepare(
        'DELETE FROM workspace_memories WHERE workspace_slug = ? AND category = ? AND key = ?',
      )
      .run(workspaceSlug, category, key);
    return info.changes > 0;
  }

  deleteMemoryById(memoryId: string): boolean {
    const info = this.db
      .prepare('DELETE FROM workspace_memories WHERE memory_id = ?')
      .run(memoryId);
    return info.changes > 0;
  }

  /**
   * Formats pinned memories and recent `task_state` entries into a deterministic Markdown recall block.
   * Returns `""` if the workspace has no pinned or `task_state` memories.
   */
  formatRecallContext(workspaceSlug: string, maxChars = 2400): string {
    assertValidWorkspaceSlug(workspaceSlug);
    if (maxChars <= 0) return '';

    const rows = this.db
      .prepare(
        `SELECT * FROM workspace_memories
         WHERE workspace_slug = ? AND (pinned = 1 OR category = 'task_state')
         ORDER BY pinned DESC, updated_at DESC
         LIMIT 50`,
      )
      .all(workspaceSlug) as WorkspaceMemoryRow[];

    if (rows.length === 0) return '';

    const header = `### Recalled Workspace Memory (${workspaceSlug})\n`;
    if (maxChars <= header.length) {
      return header.slice(0, maxChars);
    }

    const lines: string[] = [];
    let usedChars = header.length;

    for (const row of rows) {
      const mem = mapMemory(row);
      const prefix = mem.pinned ? `[PINNED:${mem.category}]` : `[${mem.category}]`;
      const compactBody = mem.content.replace(/\s+/g, ' ').trim();
      let line = `- ${prefix} \`${mem.key}\`: ${compactBody}`;
      const needed = line.length + (lines.length > 0 ? 1 : 0);

      if (usedChars + needed > maxChars) {
        const remaining = maxChars - usedChars - (lines.length > 0 ? 1 : 0);
        const linePrefix = `- ${prefix} \`${mem.key}\`: `;
        if (remaining > linePrefix.length + 12) {
          line = `${linePrefix}${compactBody.slice(0, remaining - linePrefix.length - 3)}...`;
          lines.push(line);
        }
        break;
      }

      lines.push(line);
      usedChars += needed;
    }

    if (lines.length === 0) return '';
    return `${header}${lines.join('\n')}`;
  }

  countAll(): number {
    const row = this.db
      .prepare('SELECT COUNT(*) AS cnt FROM workspace_memories')
      .get() as { cnt: number };
    return Number(row.cnt);
  }

  countByWorkspace(workspaceSlug: string): number {
    assertValidWorkspaceSlug(workspaceSlug);
    const row = this.db
      .prepare('SELECT COUNT(*) AS cnt FROM workspace_memories WHERE workspace_slug = ?')
      .get(workspaceSlug) as { cnt: number };
    return Number(row.cnt);
  }
}
