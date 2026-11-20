import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { WorkspaceRepository } from '../db/repositories/workspaceRepo.js';
import type { ScrubberLike } from '../types.js';
import { createSecretScrubber } from '../utils/secretScrubber.js';
import { createCheckpoint, isGitRepository } from './gitSnapshot.js';
import {
  checkAntiPlaceholder,
  runValidationPipeline,
  scanForSecrets,
  type ValidationDiagnostic,
  type ValidationPipelineResult,
} from './validationPipeline.js';
import {
  resolveSafeWorkspacePath,
  resolveWorkspaceRoot,
  workspaceLockManager,
  type WorkspaceLockManager,
} from './workspaceLock.js';

export interface PatchHunk {
  search: string;
  replace: string;
  line_hint?: number;
}

export interface FilePatchEdit {
  path: string;
  hunks: PatchHunk[];
}

export interface CreateOrOverwriteFileInput {
  path: string;
  content: string;
}

export interface CodePatchBaseOptions {
  workspacesDir: string;
  slug: string;
  workspaceRepo?: WorkspaceRepository;
  lockManager?: WorkspaceLockManager;
  scrubber?: ScrubberLike;
  autoCheckpoint?: boolean;
  allowPlaceholderMarkers?: boolean;
  skipValidation?: boolean;
  skipL1?: boolean;
  runHeavyChecks?: boolean;
  rollbackOnValidationFailure?: boolean;
  lineHintTolerance?: number;
  validationRunner?: typeof runValidationPipeline;
}

export interface ApplyPatchOptions extends CodePatchBaseOptions {
  edits: FilePatchEdit[];
}

export interface CreateOrOverwriteOptions extends CodePatchBaseOptions {
  files: CreateOrOverwriteFileInput[];
}

export interface DeleteFilesOptions extends CodePatchBaseOptions {
  paths: string[];
}

export interface CodePatchResult {
  action: 'patch' | 'create_or_overwrite' | 'delete_file';
  workspaceSlug: string;
  filesTouched: string[];
  checkpointId: string | null;
  diff: string;
  validation: ValidationPipelineResult | null;
  rolledBack: boolean;
}

export class CodePatchError extends Error {
  constructor(
    message: string,
    public readonly diagnostics: ValidationDiagnostic[] = [],
  ) {
    super(message);
    this.name = 'CodePatchError';
  }
}

function lineNumberAtOffset(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function findAllOccurrences(haystack: string, needle: string): number[] {
  const indices: number[] = [];
  if (!needle) return indices;
  let fromIndex = 0;
  while (fromIndex <= haystack.length - needle.length) {
    const found = haystack.indexOf(needle, fromIndex);
    if (found === -1) break;
    indices.push(found);
    fromIndex = found + needle.length;
  }
  return indices;
}

function applyHunkToBuffer(
  filePath: string,
  buffer: string,
  hunk: PatchHunk,
  lineHintTolerance: number,
): string {
  if (typeof hunk.search !== 'string' || hunk.search.length === 0) {
    throw new CodePatchError(
      `Invalid empty search block in patch for "${filePath}"; provide exact context anchors or use create_or_overwrite`,
    );
  }

  const matches = findAllOccurrences(buffer, hunk.search);
  if (matches.length === 0) {
    throw new CodePatchError(
      `Patch failed for "${filePath}": search block not found (0 matches). Ensure exact whitespace and indentation match.`,
    );
  }

  let targetOffset: number;
  if (matches.length === 1) {
    targetOffset = matches[0]!;
  } else {
    const matchLines = matches.map((offset) => ({
      offset,
      line: lineNumberAtOffset(buffer, offset),
    }));

    if (hunk.line_hint === undefined || !Number.isFinite(hunk.line_hint)) {
      throw new CodePatchError(
        `Ambiguous patch in "${filePath}": found ${matches.length} matches at lines ${matchLines.map((m) => m.line).join(', ')}. Provide more context anchors or a line_hint.`,
      );
    }

    const hint = hunk.line_hint;
    const withinTolerance = matchLines
      .map((m) => ({ ...m, distance: Math.abs(m.line - hint) }))
      .filter((m) => m.distance <= lineHintTolerance)
      .sort((a, b) => a.distance - b.distance);

    if (withinTolerance.length === 0) {
      throw new CodePatchError(
        `Ambiguous patch in "${filePath}": ${matches.length} matches at lines ${matchLines.map((m) => m.line).join(', ')}, none within ±${lineHintTolerance} lines of line_hint=${hint}.`,
      );
    }

    if (
      withinTolerance.length > 1 &&
      withinTolerance[0]!.distance === withinTolerance[1]!.distance
    ) {
      throw new CodePatchError(
        `Ambiguous patch in "${filePath}": multiple equidistant matches around line_hint=${hint} (lines ${withinTolerance[0]!.line} and ${withinTolerance[1]!.line}). Provide more context anchors.`,
      );
    }

    targetOffset = withinTolerance[0]!.offset;
  }

  return (
    buffer.slice(0, targetOffset) +
    hunk.replace +
    buffer.slice(targetOffset + hunk.search.length)
  );
}

/**
 * Generates a compact unified diff between two strings for a given relative file path.
 */
export function buildCompactUnifiedDiff(
  relPath: string,
  oldText: string | null,
  newText: string | null,
  contextLines = 3,
): string {
  const oldLines = oldText === null ? [] : oldText.split(/\r?\n/);
  const newLines = newText === null ? [] : newText.split(/\r?\n/);

  if (oldText === newText) {
    return '';
  }

  let prefix = 0;
  while (
    prefix < oldLines.length &&
    prefix < newLines.length &&
    oldLines[prefix] === newLines[prefix]
  ) {
    prefix += 1;
  }

  let suffix = 0;
  while (
    suffix < oldLines.length - prefix &&
    suffix < newLines.length - prefix &&
    oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]
  ) {
    suffix += 1;
  }

  const oldStartIdx = Math.max(0, prefix - contextLines);
  const oldEndIdx = Math.min(oldLines.length, oldLines.length - suffix + contextLines);
  const newStartIdx = Math.max(0, prefix - contextLines);
  const newEndIdx = Math.min(newLines.length, newLines.length - suffix + contextLines);

  const out: string[] = [
    `--- ${oldText === null ? '/dev/null' : `a/${relPath}`}`,
    `+++ ${newText === null ? '/dev/null' : `b/${relPath}`}`,
    `@@ -${oldStartIdx + 1},${Math.max(0, oldEndIdx - oldStartIdx)} +${newStartIdx + 1},${Math.max(0, newEndIdx - newStartIdx)} @@`,
  ];

  for (let i = oldStartIdx; i < prefix; i++) {
    out.push(` ${oldLines[i]}`);
  }
  for (let i = prefix; i < oldLines.length - suffix; i++) {
    out.push(`-${oldLines[i]}`);
  }
  for (let i = prefix; i < newLines.length - suffix; i++) {
    out.push(`+${newLines[i]}`);
  }
  for (let i = oldLines.length - suffix; i < oldEndIdx; i++) {
    out.push(` ${oldLines[i]}`);
  }

  return out.join('\n');
}

interface BackupEntry {
  absPath: string;
  existed: boolean;
  originalBytes?: Buffer;
}

function writeFileAtomically(absPath: string, content: string): void {
  const dir = path.dirname(absPath);
  fs.mkdirSync(dir, { recursive: true });
  let existingMode: number | undefined;
  try {
    if (fs.existsSync(absPath)) {
      existingMode = fs.statSync(absPath).mode & 0o777;
    }
  } catch {
    // Ignore stat errors and fall back to default mode
  }

  const tmpPath = path.join(dir, `.omni-tmp-${process.pid}-${randomUUID()}`);
  try {
    fs.writeFileSync(
      tmpPath,
      content,
      existingMode !== undefined ? { encoding: 'utf8', mode: existingMode } : { encoding: 'utf8' },
    );
    if (existingMode !== undefined && process.platform !== 'win32') {
      fs.chmodSync(tmpPath, existingMode);
    }
    fs.renameSync(tmpPath, absPath);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {
      // Ignore temp cleanup failure
    }
    throw err;
  }
}

function restoreBackups(backups: BackupEntry[]): void {
  for (let i = backups.length - 1; i >= 0; i--) {
    const entry = backups[i]!;
    try {
      if (entry.existed && entry.originalBytes !== undefined) {
        fs.mkdirSync(path.dirname(entry.absPath), { recursive: true });
        fs.writeFileSync(entry.absPath, entry.originalBytes);
      } else if (!entry.existed && fs.existsSync(entry.absPath)) {
        fs.unlinkSync(entry.absPath);
      }
    } catch {
      // Continue restoring remaining files
    }
  }
}

function preValidateContentsInMemory(
  items: Array<{ relPath: string; content: string }>,
  options: { allowPlaceholderMarkers?: boolean; scrubber: ScrubberLike },
): void {
  const diagnostics: ValidationDiagnostic[] = [];
  for (const item of items) {
    diagnostics.push(
      ...checkAntiPlaceholder(item.relPath, item.content, {
        allowPlaceholderMarkers: options.allowPlaceholderMarkers,
      }),
    );
    diagnostics.push(...scanForSecrets(item.relPath, item.content, options.scrubber));
  }

  if (diagnostics.length > 0) {
    const summary = diagnostics
      .map((d) => `${d.file}:${d.line ?? 1} [${d.rule}] ${d.message}`)
      .join('\n');
    throw new CodePatchError(
      `Pre-write validation failed (no files were modified):\n${options.scrubber.scrub(summary)}`,
      diagnostics,
    );
  }
}

async function maybeCreatePreMutationCheckpoint(
  options: CodePatchBaseOptions,
  reason: string,
  scrubber: ScrubberLike,
): Promise<string | null> {
  if (options.autoCheckpoint === false) return null;
  const { realWorkspaceRoot } = resolveWorkspaceRoot(options.workspacesDir, options.slug);
  if (!(await isGitRepository(realWorkspaceRoot))) {
    return null;
  }
  const chk = await createCheckpoint({
    workspacesDir: options.workspacesDir,
    slug: options.slug,
    reason,
    workspaceRepo: options.workspaceRepo,
    scrubber,
  });
  return chk.checkpointId;
}

/**
 * Atomically patches one or more existing files inside a workspace using exact hunk matching
 * and optional `line_hint` disambiguation.
 */
export async function applyPatch(options: ApplyPatchOptions): Promise<CodePatchResult> {
  const lockMgr = options.lockManager ?? workspaceLockManager;
  const scrubber = options.scrubber ?? createSecretScrubber();
  const tolerance = options.lineHintTolerance ?? 25;

  if (!options.edits || options.edits.length === 0) {
    throw new CodePatchError('No edits provided to applyPatch');
  }

  return lockMgr.withWriteLock(options.slug, async () => {
    const { realWorkspaceRoot } = resolveWorkspaceRoot(options.workspacesDir, options.slug);

    // 1. Resolve all paths, read originals, and compute new contents in memory
    const planned = new Map<
      string,
      { relPath: string; absPath: string; originalText: string; originalBytes: Buffer; nextText: string }
    >();

    for (const edit of options.edits) {
      const resolved = resolveSafeWorkspacePath(options.workspacesDir, options.slug, edit.path, {
        allowRoot: false,
        checkSensitive: true,
      });

      let state = planned.get(resolved.relativePath);
      if (!state) {
        if (!fs.existsSync(resolved.resolvedPath) || !fs.statSync(resolved.resolvedPath).isFile()) {
          throw new CodePatchError(`Target file does not exist: "${resolved.relativePath}"`);
        }
        const originalBytes = fs.readFileSync(resolved.resolvedPath);
        const originalText = originalBytes.toString('utf8');
        state = {
          relPath: resolved.relativePath,
          absPath: resolved.realPath,
          originalText,
          originalBytes,
          nextText: originalText,
        };
        planned.set(resolved.relativePath, state);
      }

      if (!edit.hunks || edit.hunks.length === 0) {
        throw new CodePatchError(`No hunks provided for "${resolved.relativePath}"`);
      }

      for (const hunk of edit.hunks) {
        state.nextText = applyHunkToBuffer(resolved.relativePath, state.nextText, hunk, tolerance);
      }
    }

    const plannedList = Array.from(planned.values());

    // 2. Pre-validate ALL files in memory before touching disk
    preValidateContentsInMemory(
      plannedList.map((p) => ({ relPath: p.relPath, content: p.nextText })),
      {
        allowPlaceholderMarkers: options.allowPlaceholderMarkers,
        scrubber,
      },
    );

    // 3. Auto-checkpoint on first mutation
    const checkpointId = await maybeCreatePreMutationCheckpoint(
      options,
      `code_patch:${plannedList.map((p) => p.relPath).slice(0, 3).join(',')}`,
      scrubber,
    );

    // 4. Write all files atomically with full rollback on error
    const backups: BackupEntry[] = plannedList.map((p) => ({
      absPath: p.absPath,
      existed: true,
      originalBytes: p.originalBytes,
    }));

    try {
      for (const p of plannedList) {
        writeFileAtomically(p.absPath, p.nextText);
      }
    } catch (err) {
      restoreBackups(backups);
      throw err;
    }

    const diffs = plannedList
      .map((p) => buildCompactUnifiedDiff(p.relPath, p.originalText, p.nextText))
      .filter(Boolean)
      .join('\n\n');

    // 5. Run validation pipeline (roll back backups if validation fails OR throws unexpectedly)
    let validation: ValidationPipelineResult | null = null;
    let rolledBack = false;
    if (!options.skipValidation) {
      const fileContents: Record<string, string> = {};
      for (const p of plannedList) {
        fileContents[p.relPath] = p.nextText;
      }
      try {
        const validateFn = options.validationRunner ?? runValidationPipeline;
        validation = await validateFn({
          workspaceDir: realWorkspaceRoot,
          changedFiles: plannedList.map((p) => p.relPath),
          fileContents,
          allowPlaceholderMarkers: options.allowPlaceholderMarkers,
          skipL1: options.skipL1,
          runHeavyChecks: options.runHeavyChecks,
          scrubber,
        });
      } catch (err) {
        if (options.rollbackOnValidationFailure !== false) {
          restoreBackups(backups);
        }
        throw err;
      }

      if (!validation.passed && options.rollbackOnValidationFailure !== false) {
        restoreBackups(backups);
        rolledBack = true;
      }
    }

    return {
      action: 'patch',
      workspaceSlug: options.slug,
      filesTouched: plannedList.map((p) => p.relPath),
      checkpointId,
      diff: scrubber.scrub(diffs),
      validation,
      rolledBack,
    };
  });
}

/**
 * Atomically creates or overwrites one or more files inside a workspace.
 */
export async function createOrOverwriteFiles(
  options: CreateOrOverwriteOptions,
): Promise<CodePatchResult> {
  const lockMgr = options.lockManager ?? workspaceLockManager;
  const scrubber = options.scrubber ?? createSecretScrubber();

  if (!options.files || options.files.length === 0) {
    throw new CodePatchError('No files provided to createOrOverwriteFiles');
  }

  return lockMgr.withWriteLock(options.slug, async () => {
    const { realWorkspaceRoot } = resolveWorkspaceRoot(options.workspacesDir, options.slug);

    const planned: Array<{
      relPath: string;
      absPath: string;
      existed: boolean;
      originalText: string | null;
      originalBytes?: Buffer;
      nextText: string;
    }> = [];

    for (const file of options.files) {
      const resolved = resolveSafeWorkspacePath(options.workspacesDir, options.slug, file.path, {
        allowRoot: false,
        checkSensitive: true,
      });
      const existed = fs.existsSync(resolved.resolvedPath);
      let originalBytes: Buffer | undefined;
      let originalText: string | null = null;
      if (existed) {
        if (!fs.statSync(resolved.resolvedPath).isFile()) {
          throw new CodePatchError(`Cannot overwrite non-file path "${resolved.relativePath}"`);
        }
        originalBytes = fs.readFileSync(resolved.resolvedPath);
        originalText = originalBytes.toString('utf8');
      }

      planned.push({
        relPath: resolved.relativePath,
        absPath: resolved.realPath,
        existed,
        originalText,
        originalBytes,
        nextText: file.content,
      });
    }

    preValidateContentsInMemory(
      planned.map((p) => ({ relPath: p.relPath, content: p.nextText })),
      {
        allowPlaceholderMarkers: options.allowPlaceholderMarkers,
        scrubber,
      },
    );

    const checkpointId = await maybeCreatePreMutationCheckpoint(
      options,
      `create_or_overwrite:${planned.map((p) => p.relPath).slice(0, 3).join(',')}`,
      scrubber,
    );

    const backups: BackupEntry[] = planned.map((p) => ({
      absPath: p.absPath,
      existed: p.existed,
      originalBytes: p.originalBytes,
    }));

    try {
      for (const p of planned) {
        writeFileAtomically(p.absPath, p.nextText);
      }
    } catch (err) {
      restoreBackups(backups);
      throw err;
    }

    const diffs = planned
      .map((p) => buildCompactUnifiedDiff(p.relPath, p.originalText, p.nextText))
      .filter(Boolean)
      .join('\n\n');

    let validation: ValidationPipelineResult | null = null;
    let rolledBack = false;
    if (!options.skipValidation) {
      const fileContents: Record<string, string> = {};
      for (const p of planned) {
        fileContents[p.relPath] = p.nextText;
      }
      try {
        const validateFn = options.validationRunner ?? runValidationPipeline;
        validation = await validateFn({
          workspaceDir: realWorkspaceRoot,
          changedFiles: planned.map((p) => p.relPath),
          fileContents,
          allowPlaceholderMarkers: options.allowPlaceholderMarkers,
          skipL1: options.skipL1,
          runHeavyChecks: options.runHeavyChecks,
          scrubber,
        });
      } catch (err) {
        if (options.rollbackOnValidationFailure !== false) {
          restoreBackups(backups);
        }
        throw err;
      }

      if (!validation.passed && options.rollbackOnValidationFailure !== false) {
        restoreBackups(backups);
        rolledBack = true;
      }
    }

    return {
      action: 'create_or_overwrite',
      workspaceSlug: options.slug,
      filesTouched: planned.map((p) => p.relPath),
      checkpointId,
      diff: scrubber.scrub(diffs),
      validation,
      rolledBack,
    };
  });
}

/**
 * Safely deletes one or more files inside a workspace with atomic rollback on error.
 */
export async function deleteFiles(options: DeleteFilesOptions): Promise<CodePatchResult> {
  const lockMgr = options.lockManager ?? workspaceLockManager;
  const scrubber = options.scrubber ?? createSecretScrubber();

  if (!options.paths || options.paths.length === 0) {
    throw new CodePatchError('No paths provided to deleteFiles');
  }

  return lockMgr.withWriteLock(options.slug, async () => {
    const planned: Array<{
      relPath: string;
      absPath: string;
      originalBytes: Buffer;
      originalText: string;
    }> = [];

    for (const target of options.paths) {
      const resolved = resolveSafeWorkspacePath(options.workspacesDir, options.slug, target, {
        allowRoot: false,
        checkSensitive: true,
      });
      if (!fs.existsSync(resolved.resolvedPath) || !fs.statSync(resolved.resolvedPath).isFile()) {
        throw new CodePatchError(`Cannot delete non-existent file "${resolved.relativePath}"`);
      }
      const originalBytes = fs.readFileSync(resolved.resolvedPath);
      planned.push({
        relPath: resolved.relativePath,
        absPath: resolved.realPath,
        originalBytes,
        originalText: originalBytes.toString('utf8'),
      });
    }

    const checkpointId = await maybeCreatePreMutationCheckpoint(
      options,
      `delete_file:${planned.map((p) => p.relPath).slice(0, 3).join(',')}`,
      scrubber,
    );

    const backups: BackupEntry[] = planned.map((p) => ({
      absPath: p.absPath,
      existed: true,
      originalBytes: p.originalBytes,
    }));

    try {
      for (const p of planned) {
        fs.unlinkSync(p.absPath);
      }
    } catch (err) {
      restoreBackups(backups);
      throw err;
    }

    const diffs = planned
      .map((p) => buildCompactUnifiedDiff(p.relPath, p.originalText, null))
      .filter(Boolean)
      .join('\n\n');

    return {
      action: 'delete_file',
      workspaceSlug: options.slug,
      filesTouched: planned.map((p) => p.relPath),
      checkpointId,
      diff: scrubber.scrub(diffs),
      validation: null,
      rolledBack: false,
    };
  });
}
