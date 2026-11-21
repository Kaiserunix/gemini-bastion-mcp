import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import {
  isSensitiveWorkspacePath,
  resolveSafeWorkspacePath,
  resolveWorkspaceRoot,
} from '../../core/workspaceLock.js';
import { scanForSecrets } from '../../core/validationPipeline.js';
import { buildSandboxedEnv, runSubprocess } from '../../utils/exec.js';
import type { McpToolRegistry } from '../registry.js';
import {
  buildGuardOptions,
  getToolActor,
  getWorkspaceAdapter,
  type McpToolDeps,
} from './context.js';

const ARTIFACT_ID_REGEX = /^[a-zA-Z0-9_-]{1,128}$/;
const SAFE_AST_LANG_REGEX = /^[a-zA-Z0-9_+#.-]{1,32}$/;
const MAX_READ_LINES_FILE_BYTES = 5 * 1024 * 1024;
const GIT_DIFF_SENSITIVE_EXCLUDES = [
  ':(exclude).env',
  ':(exclude).env.*',
  ':(exclude)**/.env',
  ':(exclude)**/.env.*',
  ':(exclude)*.pem',
  ':(exclude)**/*.pem',
  ':(exclude)*.key',
  ':(exclude)**/*.key',
  ':(exclude)id_rsa*',
  ':(exclude)**/id_rsa*',
  ':(exclude)id_ed25519*',
  ':(exclude)**/id_ed25519*',
  ':(exclude).dev.vars',
  ':(exclude).dev.vars.*',
  ':(exclude)**/.dev.vars',
  ':(exclude)**/.dev.vars.*',
  ':(exclude).git/**',
];
const IGNORED_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', '.next', '.turbo', '__pycache__', '.venv']);

function isBinaryMissing(exitCode: number | null, stderr: string): boolean {
  if (exitCode === 127) return true;
  const lower = stderr.toLowerCase();
  return (
    lower.includes('enoent') ||
    lower.includes('not recognized as an internal or external command') ||
    lower.includes('command not found')
  );
}

function walkWorkspaceFiles(
  rootDir: string,
  currentDir: string,
  relBase: string,
  out: string[],
  maxFiles = 500,
): void {
  if (out.length >= maxFiles) return;
  const entries = fs.readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (out.length >= maxFiles) break;
    if (IGNORED_DIRS.has(entry.name)) continue;
    const rel = relBase ? `${relBase}/${entry.name}` : entry.name;
    if (isSensitiveWorkspacePath(rel)) continue;
    const abs = path.join(currentDir, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      walkWorkspaceFiles(rootDir, abs, rel, out, maxFiles);
    } else if (entry.isFile()) {
      out.push(rel);
    }
  }
}

function fallbackPackWorkspace(targetDir: string): string {
  const files: string[] = [];
  walkWorkspaceFiles(targetDir, targetDir, '', files, 300);
  const chunks: string[] = [
    `# Workspace Pack (fallback tree: ${files.length} files)`,
    files.map((f) => `- ${f}`).join('\n'),
    '',
  ];

  let totalChars = 0;
  const maxTotalChars = 40_000;
  for (const rel of files) {
    if (totalChars >= maxTotalChars) break;
    const abs = path.join(targetDir, rel);
    try {
      const stat = fs.statSync(abs);
      if (stat.size > 32_768) continue;
      const buf = fs.readFileSync(abs);
      if (buf.includes(0)) continue;
      const text = buf.toString('utf8');
      chunks.push(`## File: ${rel}\n\`\`\`\n${text}\n\`\`\``);
      totalChars += text.length;
    } catch {
      // Skip unreadable file
    }
  }
  return chunks.join('\n\n');
}

function matchesGlob(relPath: string, globPattern: string): boolean {
  const escaped = globPattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '::GLOBSTAR::')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/::GLOBSTAR::/g, '.*');
  const re = new RegExp(`^${escaped}$`, 'i');
  return re.test(relPath) || re.test(path.basename(relPath));
}

function fallbackSearchWorkspace(
  targetDir: string,
  query: string,
  glob?: string,
  maxMatches = 200,
): string {
  const files: string[] = [];
  walkWorkspaceFiles(targetDir, targetDir, '', files, 1000);

  let matcher: RegExp;
  try {
    matcher = new RegExp(query);
  } catch {
    matcher = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  }

  const hits: string[] = [];
  for (const rel of files) {
    if (hits.length >= maxMatches) break;
    if (glob && !matchesGlob(rel, glob)) continue;
    const abs = path.join(targetDir, rel);
    try {
      const stat = fs.statSync(abs);
      if (stat.size > 512 * 1024) continue;
      const buf = fs.readFileSync(abs);
      if (buf.includes(0)) continue;
      const lines = buf.toString('utf8').split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (matcher.test(lines[i]!)) {
          hits.push(`${rel}:${i + 1}:${lines[i]}`);
          if (hits.length >= maxMatches) break;
        }
      }
    } catch {
      // Skip unreadable file
    }
  }

  return hits.length > 0 ? hits.join('\n') : '(no matches found)';
}

const SAFE_GIT_REF_REGEX = /^[A-Za-z0-9_./~^:-]+(?:\.{2,3}[A-Za-z0-9_./~^:-]+)?$/;

function assertSafeGitRef(ref: string): string {
  const trimmed = ref.trim();
  if (!trimmed || trimmed.startsWith('-') || !SAFE_GIT_REF_REGEX.test(trimmed)) {
    throw new Error(`Invalid git base_ref "${ref}": unsafe or disallowed characters.`);
  }
  return trimmed;
}

function readBoundedArtifact(artifactsDir: string, artifactId: string, offset = 0, limit = 20_000): string {
  if (!ARTIFACT_ID_REGEX.test(artifactId)) {
    throw new Error(
      `Invalid artifact_id "${artifactId}": must match ${ARTIFACT_ID_REGEX.source}`,
    );
  }

  const resolvedDir = path.resolve(artifactsDir);
  const candidate = path.resolve(resolvedDir, `${artifactId}.log`);
  const normDir = process.platform === 'win32' ? resolvedDir.toLowerCase() : resolvedDir;
  const normCand = process.platform === 'win32' ? candidate.toLowerCase() : candidate;
  if (!normCand.startsWith(normDir + path.sep)) {
    throw new Error(`Artifact path escapes artifacts directory.`);
  }
  if (!fs.existsSync(candidate)) {
    throw new Error(`Artifact "${artifactId}" not found.`);
  }

  const lstat = fs.lstatSync(candidate);
  if (lstat.isSymbolicLink() || !lstat.isFile()) {
    throw new Error(`Artifact "${artifactId}" must be a regular non-symlink file.`);
  }

  const realDir = fs.realpathSync(resolvedDir);
  const realCand = fs.realpathSync(candidate);
  const normRealDir = process.platform === 'win32' ? realDir.toLowerCase() : realDir;
  const normRealCand = process.platform === 'win32' ? realCand.toLowerCase() : realCand;
  if (!normRealCand.startsWith(normRealDir + path.sep)) {
    throw new Error(`Artifact "${artifactId}" symlink resolves outside artifacts directory.`);
  }

  const totalBytes = lstat.size;
  const safeOffset = Math.max(0, Math.min(totalBytes, Math.floor(offset)));
  const safeLimit = Math.max(1, Math.min(50_000, Math.floor(limit)));
  const bytesToRead = Math.max(0, Math.min(safeLimit, totalBytes - safeOffset));

  let slice = '';
  if (bytesToRead > 0) {
    const buf = Buffer.allocUnsafe(bytesToRead);
    const fd = fs.openSync(realCand, 'r');
    try {
      let readSoFar = 0;
      while (readSoFar < bytesToRead) {
        const n = fs.readSync(fd, buf, readSoFar, bytesToRead - readSoFar, safeOffset + readSoFar);
        if (n <= 0) break;
        readSoFar += n;
      }
      slice = buf.subarray(0, readSoFar).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  }

  const nextOffset = safeOffset + bytesToRead;
  const hasMore = nextOffset < totalBytes;

  return [
    `# Artifact: ${artifactId}`,
    `Total bytes: ${totalBytes} | Offset: ${safeOffset} | Returned: ${bytesToRead} | HasMore: ${hasMore}${hasMore ? ` (next offset=${nextOffset})` : ''}`,
    '---',
    slice,
  ].join('\n');
}

function assertSafeAstLang(lang: string): string {
  const trimmed = lang.trim();
  if (!trimmed || trimmed.startsWith('-') || !SAFE_AST_LANG_REGEX.test(trimmed)) {
    throw new Error(`Invalid ast lang "${lang}": unsafe or disallowed characters.`);
  }
  return trimmed;
}

function filterSensitiveAstOutput(output: string, realWorkspaceRoot: string): string {
  const normalizedRoot = realWorkspaceRoot.replace(/\\/g, '/').replace(/\/+$/, '');
  const kept: string[] = [];
  for (const line of output.split(/\r?\n/)) {
    const candidateMatch = /^([^:\s][^:]*?)(?::\d+|$)/.exec(line.trim());
    if (candidateMatch?.[1]) {
      let rel = candidateMatch[1].replace(/\\/g, '/');
      if (rel.toLowerCase().startsWith(normalizedRoot.toLowerCase() + '/')) {
        rel = rel.slice(normalizedRoot.length + 1);
      }
      if (isSensitiveWorkspacePath(rel)) {
        continue;
      }
    }
    kept.push(line);
  }
  return kept.join('\n').trim();
}

export function registerWorkspaceTools(registry: McpToolRegistry, deps: McpToolDeps): void {
  const wsAdapter = getWorkspaceAdapter(deps);

  // 1. workspace_manage
  registry.register({
    name: 'workspace_manage',
    title: 'Manage Workspaces, Checkpoints & Persistent Memory',
    description:
      'List registered workspaces, sync GitHub repos into /workspaces/{slug}, inspect Cloudflare wrangler ops context, list/rollback checkpoints, and read/write/delete persistent workspace memories.',
    inputSchema: {
      action: z.enum([
        'list',
        'sync_github',
        'init_cf_ops',
        'list_checkpoints',
        'rollback',
        'memory_list',
        'memory_upsert',
        'memory_delete',
      ]),
      slug: z.string().optional(),
      repo: z.string().optional(),
      branch: z.string().optional(),
      checkpoint_id: z.string().optional(),
      limit: z.number().int().min(1).max(100).optional(),
      memory_category: z
        .enum(['task_state', 'decision', 'pitfall', 'preference', 'note'])
        .optional(),
      memory_key: z.string().min(1).max(80).optional(),
      memory_content: z.string().min(1).max(8192).optional(),
      memory_pinned: z.boolean().optional(),
      memory_id: z.string().min(1).max(128).optional(),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `workspace-${args.action}`),
      requiredScope: ['list', 'init_cf_ops', 'list_checkpoints', 'memory_list'].includes(
        args.action,
      )
        ? 'read'
        : 'write',
    }),
    handler: async (args, extra) => {
      const actor = getToolActor(deps, extra);

      switch (args.action) {
        case 'list': {
          const workspaces = deps.repos.workspaces.listWorkspaces();
          if (workspaces.length === 0) {
            return 'No workspaces registered yet. Use workspace_manage(action="sync_github", slug=..., repo=...) to clone one.';
          }
          const lines = workspaces.map((w) => {
            const baseLine = `- ${w.slug} | repo=${w.repo_url} | branch=${w.default_branch} | langs=${w.detected_stack.languages.join(',') || 'unknown'} | synced=${w.last_synced_at ? new Date(w.last_synced_at).toISOString() : 'never'}`;
            const memories = deps.repos.memories.listMemories({
              workspaceSlug: w.slug,
              limit: 10,
            });
            const highlight = memories
              .filter((m) => m.pinned || m.category === 'task_state')
              .slice(0, 3);
            if (highlight.length === 0) {
              return baseLine;
            }
            const snippets = highlight.map((m) => {
              const compact = m.content.replace(/\s+/g, ' ').trim();
              const preview = compact.length > 90 ? `${compact.slice(0, 87)}...` : compact;
              return `  - [${m.category}/${m.key}${m.pinned ? ' pinned' : ''}] ${preview}`;
            });
            return `${baseLine}\n${snippets.join('\n')}`;
          });
          return `# Registered Workspaces (${workspaces.length})\n${lines.join('\n')}`;
        }

        case 'sync_github': {
          if (!args.slug || !args.repo) {
            throw new Error('sync_github requires both "slug" and "repo".');
          }
          const res = await deps.lockManager.withWriteLock(args.slug, () =>
            wsAdapter.syncGitHubRepo({
              workspacesDir: deps.config.workspacesDir,
              slug: args.slug!,
              repo: args.repo!,
              branch: args.branch,
              ghToken: deps.config.ghToken,
              workspaceRepo: deps.repos.workspaces,
              scrubber: deps.scrubber,
            }),
          );
          deps.repos.audit.record({
            actor,
            action: 'workspace.sync_github',
            target: res.workspace.slug,
            status: 'success',
            details: { repo: res.workspace.repo_url, branch: res.currentBranch, action: res.action },
          });
          const recall = deps.repos.memories.formatRecallContext(res.workspace.slug);
          return [
            `Workspace "${res.workspace.slug}" ${res.action} on branch "${res.currentBranch}" (${res.headSha.slice(0, 8)}).`,
            `Languages: ${res.workspace.detected_stack.languages.join(', ') || 'none'}`,
            `Frameworks: ${res.workspace.detected_stack.frameworks.join(', ') || 'none'}`,
            res.workspace.playbook_text
              ? `Playbook detected (${res.workspace.detected_stack.playbookSources?.join(', ')})`
              : 'No AGENTS.md/CLAUDE.md playbook found.',
            res.output ? `\n${res.output}` : '',
            recall ? `\n${recall}` : '',
          ].join('\n');
        }

        case 'init_cf_ops': {
          if (!args.slug) {
            throw new Error('init_cf_ops requires "slug".');
          }
          const ctx = await deps.lockManager.withReadLock(args.slug, async () =>
            wsAdapter.initCfOpsWorkspace({
              workspacesDir: deps.config.workspacesDir,
              slug: args.slug!,
              workspaceRepo: deps.repos.workspaces,
            }),
          );
          const recall = deps.repos.memories.formatRecallContext(ctx.workspaceSlug);
          return JSON.stringify(
            recall ? { ...ctx, recalled_memories: recall } : ctx,
            null,
            2,
          );
        }

        case 'list_checkpoints': {
          if (!args.slug) {
            throw new Error('list_checkpoints requires "slug".');
          }
          const { slug } = resolveWorkspaceRoot(deps.config.workspacesDir, args.slug);
          const checkpoints = deps.repos.workspaces.listCheckpoints(slug, args.limit ?? 20);
          if (checkpoints.length === 0) {
            return `No checkpoints found for workspace "${slug}".`;
          }
          const lines = checkpoints.map(
            (c) =>
              `- ${c.checkpoint_id} | sha=${c.git_commit_sha.slice(0, 10)} | reason=${c.reason} | ${new Date(c.created_at).toISOString()}`,
          );
          return `# Checkpoints for ${slug} (${checkpoints.length})\n${lines.join('\n')}`;
        }

        case 'rollback': {
          if (!args.slug || !args.checkpoint_id) {
            throw new Error('rollback requires both "slug" and "checkpoint_id".');
          }
          const rb = await deps.lockManager.withWriteLock(args.slug, () =>
            wsAdapter.rollbackToCheckpoint(args.slug!, args.checkpoint_id!, {
              workspacesDir: deps.config.workspacesDir,
              workspaceRepo: deps.repos.workspaces,
              createSafetyCheckpoint: true,
              scrubber: deps.scrubber,
            }),
          );
          deps.repos.audit.record({
            actor,
            action: 'workspace.rollback',
            target: `${rb.workspaceSlug}:${rb.rolledBackTo}`,
            status: 'success',
            details: {
              git_commit_sha: rb.gitCommitSha,
              safety_checkpoint_id: rb.safetyCheckpointId,
            },
          });
          return [
            `Rolled back workspace "${rb.workspaceSlug}" to checkpoint "${rb.rolledBackTo}" (${rb.gitCommitSha.slice(0, 10)}).`,
            rb.safetyCheckpointId ? `Safety checkpoint created: ${rb.safetyCheckpointId}` : '',
          ]
            .filter(Boolean)
            .join('\n');
        }

        case 'memory_list': {
          const safeSlug = args.slug
            ? resolveWorkspaceRoot(deps.config.workspacesDir, args.slug).slug
            : undefined;
          const records = deps.repos.memories.listMemories({
            ...(safeSlug ? { workspaceSlug: safeSlug } : {}),
            ...(args.memory_category ? { category: args.memory_category } : {}),
            ...(args.memory_pinned !== undefined ? { pinnedOnly: args.memory_pinned } : {}),
            limit: args.limit ?? 50,
          });
          if (records.length === 0) {
            return safeSlug
              ? `No persistent memories found for workspace "${safeSlug}".`
              : 'No persistent memories found.';
          }
          const lines = records.map(
            (m) =>
              `- [${m.workspace_slug}] (${m.category}) ${m.key}${m.pinned ? ' [pinned]' : ''} | id=${m.memory_id} | updated=${new Date(m.updated_at).toISOString()}\n  ${m.content}`,
          );
          return `# Workspace Memories (${records.length})\n${lines.join('\n')}`;
        }

        case 'memory_upsert': {
          if (!args.slug || !args.memory_key || !args.memory_content) {
            throw new Error(
              'memory_upsert requires "slug", "memory_key", and "memory_content".',
            );
          }
          const { slug } = resolveWorkspaceRoot(deps.config.workspacesDir, args.slug);
          const category = args.memory_category ?? 'note';
          const secretDiagnostics = scanForSecrets(
            `memory/${slug}/${category}/${args.memory_key}`,
            args.memory_content,
            deps.scrubber,
          );
          if (secretDiagnostics.length > 0) {
            const rules = Array.from(new Set(secretDiagnostics.map((d) => d.rule))).join(', ');
            throw new Error(
              `Refusing to persist workspace memory: secret pattern detected (${rules}). Never store tokens, API keys, or private keys in memory.`,
            );
          }

          const scrubbedContent = deps.scrubber.scrub(args.memory_content);
          const record = deps.repos.memories.upsertMemory({
            workspaceSlug: slug,
            category,
            key: args.memory_key,
            content: scrubbedContent,
            pinned: args.memory_pinned ?? false,
          });
          deps.repos.audit.record({
            actor,
            action: 'workspace.memory_upsert',
            target: `${slug}:${category}:${record.key}`,
            status: 'success',
            details: { memory_id: record.memory_id, pinned: record.pinned },
          });
          return `Saved persistent memory "${record.key}" (${record.category}, pinned=${record.pinned}) for workspace "${record.workspace_slug}" [memory_id=${record.memory_id}].`;
        }

        case 'memory_delete': {
          if (args.memory_id) {
            const existing = deps.repos.memories.getMemoryById(args.memory_id);
            if (!existing) {
              throw new Error(`Memory "${args.memory_id}" not found.`);
            }
            if (args.slug) {
              const { slug } = resolveWorkspaceRoot(deps.config.workspacesDir, args.slug);
              if (existing.workspace_slug !== slug) {
                throw new Error(
                  `Memory "${args.memory_id}" belongs to workspace "${existing.workspace_slug}", not "${slug}".`,
                );
              }
            }
            const deleted = deps.repos.memories.deleteMemoryById(args.memory_id);
            if (!deleted) {
              throw new Error(`Failed to delete memory "${args.memory_id}".`);
            }
            deps.repos.audit.record({
              actor,
              action: 'workspace.memory_delete',
              target: `${existing.workspace_slug}:${existing.category}:${existing.key}`,
              status: 'success',
              details: { memory_id: existing.memory_id },
            });
            return `Deleted memory "${existing.key}" (${existing.category}) from workspace "${existing.workspace_slug}" [memory_id=${existing.memory_id}].`;
          }

          if (!args.slug || !args.memory_key) {
            throw new Error(
              'memory_delete requires either "memory_id" or ("slug", "memory_key", and optional "memory_category").',
            );
          }
          const { slug } = resolveWorkspaceRoot(deps.config.workspacesDir, args.slug);
          const category = args.memory_category ?? 'note';
          const deleted = deps.repos.memories.deleteMemory(slug, category, args.memory_key);
          if (!deleted) {
            throw new Error(
              `Memory (${category}/${args.memory_key}) not found for workspace "${slug}".`,
            );
          }
          deps.repos.audit.record({
            actor,
            action: 'workspace.memory_delete',
            target: `${slug}:${category}:${args.memory_key}`,
            status: 'success',
          });
          return `Deleted memory "${args.memory_key}" (${category}) from workspace "${slug}".`;
        }
      }
    },
  });

  // 2. code_explore
  registry.register({
    name: 'code_explore',
    title: 'Explore Code & Artifacts',
    description:
      'Read-only code exploration: pack repository, search text/regex, AST pattern search, read_lines, read_artifact (offloaded outputs), or git_diff.',
    inputSchema: {
      mode: z.enum(['pack', 'search', 'ast', 'read_lines', 'read_artifact', 'git_diff']),
      slug: z.string().optional(),
      path: z.string().optional(),
      query: z.string().optional(),
      glob: z.string().optional(),
      lang: z.string().optional(),
      start_line: z.number().int().min(1).optional(),
      end_line: z.number().int().min(1).optional(),
      artifact_id: z.string().optional(),
      offset: z.number().int().min(0).optional(),
      limit: z.number().int().min(1).max(50000).optional(),
      staged: z.boolean().optional(),
      base_ref: z.string().optional(),
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `explore-${args.mode}`),
      requiredScope: 'read',
    }),
    handler: async (args) => {
      if (args.mode === 'read_artifact') {
        if (!args.artifact_id) {
          throw new Error('read_artifact mode requires "artifact_id".');
        }
        return readBoundedArtifact(
          deps.config.artifactsDir,
          args.artifact_id,
          args.offset ?? 0,
          args.limit ?? 20_000,
        );
      }

      if (!args.slug) {
        throw new Error(`code_explore mode "${args.mode}" requires "slug".`);
      }
      const slug = args.slug;

      return deps.lockManager.withReadLock(slug, async () => {
        switch (args.mode) {
          case 'pack': {
            const target = resolveSafeWorkspacePath(
              deps.config.workspacesDir,
              slug,
              args.path ?? '.',
              { allowRoot: true, checkSensitive: true },
            );
            const res = await runSubprocess({
              command: 'repomix',
              args: [
                '--stdout',
                '--compress',
                '--ignore',
                '**/.env,**/.env.*,**/*.pem,**/*.key,**/id_rsa*,**/id_ed25519*,**/.dev.vars,**/.dev.vars.*',
                target.realPath,
              ],
              cwd: target.realWorkspaceRoot,
              env: buildSandboxedEnv(),
              timeoutMs: 15_000,
              maxOutputBytes: 512 * 1024,
            });
            if (res.exitCode === 0 && res.stdout.trim()) {
              return res.stdout;
            }
            return fallbackPackWorkspace(target.realPath);
          }

          case 'search': {
            if (!args.query) {
              throw new Error('search mode requires "query".');
            }
            const target = resolveSafeWorkspacePath(
              deps.config.workspacesDir,
              slug,
              args.path ?? '.',
              { allowRoot: true, checkSensitive: true },
            );
            const rgArgs = ['--line-number', '--no-heading', '--color=never'];
            if (args.glob) {
              if (args.glob.includes('\0') || args.glob.trim().startsWith('-')) {
                throw new Error(`Invalid glob "${args.glob}".`);
              }
              rgArgs.push('--glob', args.glob);
            }
            // Negative sensitive globs placed AFTER args.glob so later flags cannot re-include secrets
            rgArgs.push(
              '--glob',
              '!.env',
              '--glob',
              '!.env.*',
              '--glob',
              '!*.pem',
              '--glob',
              '!*.key',
              '--glob',
              '!id_rsa*',
              '--glob',
              '!id_ed25519*',
              '--glob',
              '!.dev.vars',
              '--glob',
              '!.dev.vars.*',
              '--glob',
              '!.git/**',
            );
            rgArgs.push('--', args.query, target.realPath);

            const res = await runSubprocess({
              command: 'rg',
              args: rgArgs,
              cwd: target.realWorkspaceRoot,
              env: buildSandboxedEnv(),
              timeoutMs: 10_000,
              maxOutputBytes: 512 * 1024,
            });
            if (isBinaryMissing(res.exitCode, res.stderr)) {
              return fallbackSearchWorkspace(target.realPath, args.query, args.glob);
            }
            if (res.exitCode === 1) {
              return '(no matches found)';
            }
            if (res.exitCode !== 0) {
              throw new Error(`rg search failed: ${res.stderr || res.stdout}`);
            }
            return res.stdout || '(no matches found)';
          }

          case 'ast': {
            if (!args.query) {
              throw new Error('ast mode requires "query" (AST pattern).');
            }
            const target = resolveSafeWorkspacePath(
              deps.config.workspacesDir,
              slug,
              args.path ?? '.',
              { allowRoot: true, checkSensitive: true },
            );
            const sgArgs = ['--pattern', args.query];
            if (args.lang) {
              sgArgs.push('--lang', assertSafeAstLang(args.lang));
            }
            sgArgs.push('--', target.realPath);

            const res = await runSubprocess({
              command: 'ast-grep',
              args: sgArgs,
              cwd: target.realWorkspaceRoot,
              env: buildSandboxedEnv(),
              timeoutMs: 10_000,
              maxOutputBytes: 512 * 1024,
            });
            if (isBinaryMissing(res.exitCode, res.stderr)) {
              return `ast-grep binary not installed on host; falling back to text search:\n${fallbackSearchWorkspace(target.realPath, args.query, args.glob)}`;
            }
            if (res.exitCode !== 0 && !res.stdout.trim()) {
              return res.stderr.trim() || '(no AST matches found)';
            }
            const filtered = filterSensitiveAstOutput(res.stdout, target.realWorkspaceRoot);
            return filtered || '(no AST matches found)';
          }

          case 'read_lines': {
            if (!args.path) {
              throw new Error('read_lines mode requires "path".');
            }
            const target = resolveSafeWorkspacePath(
              deps.config.workspacesDir,
              slug,
              args.path,
              { allowRoot: false, checkSensitive: true },
            );
            if (!fs.existsSync(target.realPath) || !fs.statSync(target.realPath).isFile()) {
              throw new Error(`File not found: "${target.relativePath}"`);
            }
            const fileSize = fs.statSync(target.realPath).size;
            if (fileSize > MAX_READ_LINES_FILE_BYTES) {
              throw new Error(
                `File "${target.relativePath}" exceeds 5MB read_lines limit (${fileSize} bytes). Use search or read_artifact.`,
              );
            }
            const lines = fs.readFileSync(target.realPath, 'utf8').split(/\r?\n/);
            const startLine = Math.max(1, args.start_line ?? 1);
            const endLine = Math.min(lines.length, args.end_line ?? startLine + 199);
            const numbered: string[] = [];
            for (let i = startLine; i <= endLine; i++) {
              numbered.push(`${i}: ${lines[i - 1] ?? ''}`);
            }
            return [
              `# ${target.relativePath} (lines ${startLine}-${endLine} of ${lines.length})`,
              numbered.join('\n'),
            ].join('\n');
          }

          case 'git_diff': {
            const target = resolveSafeWorkspacePath(
              deps.config.workspacesDir,
              slug,
              args.path ?? '.',
              { allowRoot: true, checkSensitive: true },
            );
            const gitArgs = ['diff'];
            if (args.staged) gitArgs.push('--staged');
            if (args.base_ref) gitArgs.push(assertSafeGitRef(args.base_ref));
            gitArgs.push(
              '--',
              target.relativePath !== '.' ? target.relativePath : '.',
              ...GIT_DIFF_SENSITIVE_EXCLUDES,
            );
            const res = await runSubprocess({
              command: 'git',
              args: gitArgs,
              cwd: target.realWorkspaceRoot,
              env: buildSandboxedEnv(),
              timeoutMs: 10_000,
              maxOutputBytes: 512 * 1024,
            });
            if (res.exitCode !== 0) {
              throw new Error(`git diff failed: ${res.stderr || res.stdout}`);
            }
            return res.stdout.trim() || '(no diff)';
          }
        }
      });
    },
  });

  // 3. code_patch
  registry.register({
    name: 'code_patch',
    title: 'Patch Workspace Files',
    description:
      'Atomically patch existing files with exact hunks (search/replace or old_text/new_text), create_or_overwrite files, or delete files inside a workspace, with auto-checkpoint and L0/L1/L2 validation.',
    inputSchema: {
      action: z.enum(['patch', 'create_or_overwrite', 'delete_file']),
      slug: z.string().min(1),
      edits: z
        .array(
          z.object({
            path: z.string().min(1),
            hunks: z.array(
              z
                .object({
                  search: z.string().optional(),
                  replace: z.string().optional(),
                  old_text: z.string().optional(),
                  new_text: z.string().optional(),
                  line_hint: z.number().int().min(1).optional(),
                })
                .refine(
                  (h) =>
                    (h.search !== undefined && h.replace !== undefined) ||
                    (h.old_text !== undefined && h.new_text !== undefined),
                  'Each hunk must provide either (search, replace) or (old_text, new_text).',
                ),
            ),
          }),
        )
        .optional(),
      files: z
        .array(
          z.object({
            path: z.string().min(1),
            content: z.string(),
          }),
        )
        .optional(),
      paths: z.array(z.string().min(1)).optional(),
      allow_placeholder_markers: z.boolean().optional(),
      skip_validation: z.boolean().optional(),
      skip_l1: z.boolean().optional(),
      run_heavy_checks: z.boolean().optional(),
      rollback_on_failure: z.boolean().optional(),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `patch-${args.slug}`),
      requiredScope: 'write',
    }),
    handler: async (args, extra) => {
      const actor = getToolActor(deps, extra);
      const common = {
        workspacesDir: deps.config.workspacesDir,
        slug: args.slug,
        workspaceRepo: deps.repos.workspaces,
        lockManager: deps.lockManager,
        scrubber: deps.scrubber,
        allowPlaceholderMarkers: args.allow_placeholder_markers,
        skipValidation: args.skip_validation,
        skipL1: args.skip_l1,
        runHeavyChecks: args.run_heavy_checks,
        rollbackOnValidationFailure: args.rollback_on_failure,
      };

      let res;
      if (args.action === 'patch') {
        if (!args.edits?.length) {
          throw new Error('patch action requires non-empty "edits".');
        }
        const normalizedEdits = args.edits.map((edit) => ({
          path: edit.path,
          hunks: edit.hunks.map((h) => ({
            search: h.search ?? h.old_text ?? '',
            replace: h.replace ?? h.new_text ?? '',
            line_hint: h.line_hint,
          })),
        }));
        res = await wsAdapter.applyPatch({ ...common, edits: normalizedEdits });
      } else if (args.action === 'create_or_overwrite') {
        if (!args.files?.length) {
          throw new Error('create_or_overwrite action requires non-empty "files".');
        }
        res = await wsAdapter.createOrOverwriteFiles({ ...common, files: args.files });
      } else {
        if (!args.paths?.length) {
          throw new Error('delete_file action requires non-empty "paths".');
        }
        res = await wsAdapter.deleteFiles({ ...common, paths: args.paths });
      }

      deps.repos.audit.record({
        actor,
        action: `code_patch.${args.action}`,
        target: args.slug,
        status: res.rolledBack ? 'failure' : 'success',
        details: {
          files: res.filesTouched,
          checkpoint_id: res.checkpointId,
          rolled_back: res.rolledBack,
        },
      });

      return [
        `# code_patch (${res.action}) @ ${res.workspaceSlug}`,
        `Files touched: ${res.filesTouched.join(', ')}`,
        `Checkpoint: ${res.checkpointId ?? 'none'} | RolledBack: ${res.rolledBack}`,
        res.validation ? `Validation: ${res.validation.summary}` : 'Validation: skipped',
        res.diff ? `\n## Diff\n${res.diff}` : '',
      ]
        .filter(Boolean)
        .join('\n');
    },
  });
}
