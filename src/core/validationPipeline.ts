import fs from 'node:fs';
import path from 'node:path';
import type {
  ScrubberLike,
  ValidationLevel,
  ValidationResult,
  ValidationStepResult,
} from '../types.js';
import { buildSandboxedEnv, runSubprocess } from '../utils/exec.js';
import { createSecretScrubber } from '../utils/secretScrubber.js';
import { detectWorkspaceStackAndPlaybook } from './gitSnapshot.js';

export interface ValidationDiagnostic {
  file: string;
  line?: number;
  column?: number;
  rule: string;
  message: string;
}

export interface FileContentInput {
  path: string;
  content: string;
}

export interface ValidationPipelineOptions {
  workspaceDir: string;
  changedFiles: string[];
  /** Optional in-memory contents for changed files (avoids disk re-read during preflight). */
  fileContents?: Record<string, string>;
  allowPlaceholderMarkers?: boolean;
  skipL1?: boolean;
  skipL2?: boolean;
  runHeavyChecks?: boolean;
  syncBudgetMs?: number;
  l1BudgetMs?: number;
  scrubber?: ScrubberLike;
}

export interface ValidationPipelineResult extends ValidationResult {
  diagnostics: ValidationDiagnostic[];
}

const PLACEHOLDER_EXCLUDED_EXTENSIONS = new Set(['.md', '.txt', '.json']);

const COMMENT_PLACEHOLDER_PATTERNS: RegExp[] = [
  /^\s*(?:\/\/|#|\/\*|<!--)\s*\.\.\.\s*(?:existing|rest|unchanged|omitted|remaining|more|skip|placeholder|code|保持不变|省略)/i,
  /^\s*(?:\/\/|#)\s*\.{3,}\s*(?:existing|rest|unchanged|保持不变|省略)?\s*$/i,
];

const CONFLICT_MARKER_PATTERNS: RegExp[] = [
  /^<{7}(?:\s|$)/,
  /^={7}\s*$/,
  /^>{7}(?:\s|$)/,
];

const EXTRA_SECRET_PATTERNS: Array<{ rule: string; regex: RegExp }> = [
  { rule: 'aws-access-key', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  {
    rule: 'private-key-header',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
  },
  { rule: 'stripe-secret-key', regex: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b/ },
  { rule: 'slack-token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { rule: 'google-api-key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
];

/**
 * Checks a file's text for lazy truncation placeholders and git conflict markers.
 * Excludes `.md`, `.txt`, and `.json`, and honors `allowPlaceholderMarkers`.
 */
export function checkAntiPlaceholder(
  filePath: string,
  content: string,
  options: { allowPlaceholderMarkers?: boolean } = {},
): ValidationDiagnostic[] {
  if (options.allowPlaceholderMarkers) {
    return [];
  }

  const ext = path.extname(filePath).toLowerCase();
  if (PLACEHOLDER_EXCLUDED_EXTENSIONS.has(ext)) {
    return [];
  }

  const diagnostics: ValidationDiagnostic[] = [];
  const lines = content.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx]!;
    const lineNum = idx + 1;

    let matched = false;
    for (const pattern of COMMENT_PLACEHOLDER_PATTERNS) {
      if (pattern.test(line)) {
        diagnostics.push({
          file: filePath,
          line: lineNum,
          column: 1,
          rule: 'anti-placeholder',
          message: `Rejected placeholder/truncation marker on line ${lineNum}: "${line.trim()}"`,
        });
        matched = true;
        break;
      }
    }
    if (matched) continue;

    for (const conflictPattern of CONFLICT_MARKER_PATTERNS) {
      if (conflictPattern.test(line)) {
        diagnostics.push({
          file: filePath,
          line: lineNum,
          column: 1,
          rule: 'conflict-marker',
          message: `Rejected unresolved merge conflict marker on line ${lineNum}: "${line.trim()}"`,
        });
        break;
      }
    }
  }

  return diagnostics;
}

/**
 * In-process secret leak scan using SecretScrubber plus high-confidence key regexes.
 */
export function scanForSecrets(
  filePath: string,
  content: string,
  scrubber: ScrubberLike = createSecretScrubber(),
): ValidationDiagnostic[] {
  const diagnostics: ValidationDiagnostic[] = [];
  const lines = content.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx]!;
    const lineNum = idx + 1;

    if (scrubber.scrub(line) !== line) {
      diagnostics.push({
        file: filePath,
        line: lineNum,
        column: 1,
        rule: 'secret-leak',
        message: `Potential hardcoded secret or token detected on line ${lineNum} of "${filePath}"`,
      });
      continue;
    }

    for (const extra of EXTRA_SECRET_PATTERNS) {
      if (extra.regex.test(line)) {
        diagnostics.push({
          file: filePath,
          line: lineNum,
          column: 1,
          rule: `secret-leak:${extra.rule}`,
          message: `Potential hardcoded secret (${extra.rule}) detected on line ${lineNum} of "${filePath}"`,
        });
        break;
      }
    }
  }

  return diagnostics;
}

function offsetToLineColumn(content: string, offset: number): { line: number; column: number } {
  const bounded = Math.max(0, Math.min(offset, content.length));
  const prefix = content.slice(0, bounded);
  const lines = prefix.split('\n');
  const line = lines.length;
  const column = (lines[lines.length - 1]?.length ?? 0) + 1;
  return { line, column };
}

/**
 * In-process L0 syntax validator for `.json` and `.ts/.tsx/.js/.jsx/.mts/.cts/.mjs/.cjs`.
 */
export async function checkSyntax(
  filePath: string,
  content: string,
): Promise<ValidationDiagnostic[]> {
  const ext = path.extname(filePath).toLowerCase();

  if (ext === '.json') {
    try {
      JSON.parse(content);
      return [];
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      let line = 1;
      let column = 1;

      const tsMod = await import('typescript').catch(() => null);
      if (tsMod) {
        const ts = tsMod.default ?? tsMod;
        const jsonSf = ts.parseJsonText(filePath, content);
        const parseDiags = (
          jsonSf as unknown as {
            parseDiagnostics?: Array<{
              start?: number;
              messageText: string | import('typescript').DiagnosticMessageChain;
            }>;
          }
        ).parseDiagnostics;
        if (parseDiags && parseDiags.length > 0 && typeof parseDiags[0]!.start === 'number') {
          const pos = jsonSf.getLineAndCharacterOfPosition(parseDiags[0]!.start);
          line = pos.line + 1;
          column = pos.character + 1;
        }
      }

      if (line === 1 && column === 1) {
        const lineColMatch = msg.match(/line\s+(\d+)\s+column\s+(\d+)/i);
        const posMatch = msg.match(/position\s+(\d+)/i);
        if (lineColMatch) {
          line = Number(lineColMatch[1]);
          column = Number(lineColMatch[2]);
        } else if (posMatch) {
          const loc = offsetToLineColumn(content, Number(posMatch[1]));
          line = loc.line;
          column = loc.column;
        }
      }

      return [
        {
          file: filePath,
          line,
          column,
          rule: 'json-syntax',
          message: `JSON syntax error in "${filePath}" at ${line}:${column}: ${msg}`,
        },
      ];
    }
  }

  const tsExts = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']);
  if (tsExts.has(ext)) {
    const tsMod = await import('typescript').catch(() => null);
    if (!tsMod) {
      return [];
    }
    const ts = tsMod.default ?? tsMod;

    let scriptKind = ts.ScriptKind.TS;
    if (ext === '.tsx') scriptKind = ts.ScriptKind.TSX;
    else if (ext === '.jsx') scriptKind = ts.ScriptKind.JSX;
    else if (ext === '.js' || ext === '.mjs' || ext === '.cjs') scriptKind = ts.ScriptKind.JS;

    const sourceFile = ts.createSourceFile(
      filePath,
      content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind,
    );

    const parseDiagnostics =
      (
        sourceFile as unknown as {
          parseDiagnostics?: Array<{
            start?: number;
            messageText: string | import('typescript').DiagnosticMessageChain;
          }>;
        }
      ).parseDiagnostics ?? [];

    return parseDiagnostics.map((diag) => {
      const pos =
        typeof diag.start === 'number'
          ? sourceFile.getLineAndCharacterOfPosition(diag.start)
          : { line: 0, character: 0 };
      const line = pos.line + 1;
      const column = pos.character + 1;
      const text = ts.flattenDiagnosticMessageText(diag.messageText, ' ');
      return {
        file: filePath,
        line,
        column,
        rule: 'ts-syntax',
        message: `Syntax error in "${filePath}" at ${line}:${column}: ${text}`,
      };
    });
  }

  return [];
}

/**
 * Runs L0 in-memory checks (anti-placeholder, secret scan, syntax) across a batch of files.
 */
export async function runL0Preflight(
  files: FileContentInput[],
  options: { allowPlaceholderMarkers?: boolean; scrubber?: ScrubberLike } = {},
): Promise<{
  passed: boolean;
  diagnostics: ValidationDiagnostic[];
  step: ValidationStepResult;
}> {
  const startedAt = Date.now();
  const scrubber = options.scrubber ?? createSecretScrubber();
  const diagnostics: ValidationDiagnostic[] = [];

  for (const file of files) {
    diagnostics.push(
      ...checkAntiPlaceholder(file.path, file.content, {
        allowPlaceholderMarkers: options.allowPlaceholderMarkers,
      }),
    );
    diagnostics.push(...scanForSecrets(file.path, file.content, scrubber));
    diagnostics.push(...(await checkSyntax(file.path, file.content)));
  }

  const passed = diagnostics.length === 0;
  const output = diagnostics
    .map((d) => `${d.file}:${d.line ?? 1}:${d.column ?? 1} [${d.rule}] ${d.message}`)
    .join('\n');

  return {
    passed,
    diagnostics,
    step: {
      level: 'L0',
      tool: 'l0-in-process',
      passed,
      exitCode: passed ? 0 : 1,
      summary: passed
        ? `L0 checks passed for ${files.length} file(s)`
        : `L0 checks failed with ${diagnostics.length} diagnostic(s)`,
      output: scrubber.scrub(output),
      durationMs: Date.now() - startedAt,
    },
  };
}

function isBinaryMissingOutput(exitCode: number | null, stderr: string): boolean {
  if (exitCode === 127) return true;
  const lower = stderr.toLowerCase();
  return (
    lower.includes('enoent') ||
    lower.includes('not recognized as an internal or external command') ||
    lower.includes('command not found')
  );
}

async function runLinterStep(
  workspaceDir: string,
  tool: string,
  command: string,
  args: string[],
  timeoutMs: number,
  scrubber: ScrubberLike,
): Promise<ValidationStepResult> {
  const startedAt = Date.now();
  if (timeoutMs <= 50) {
    return {
      level: 'L1',
      tool,
      passed: true,
      exitCode: null,
      skipped: true,
      summary: `${tool} skipped (sync budget exhausted)`,
      output: '',
      durationMs: 0,
    };
  }

  const res = await runSubprocess({
    command,
    args,
    cwd: workspaceDir,
    env: buildSandboxedEnv(),
    timeoutMs,
    maxOutputBytes: 64 * 1024,
  });

  if (res.timedOut) {
    return {
      level: 'L1',
      tool,
      passed: true,
      exitCode: null,
      skipped: true,
      summary: `${tool} timed out after ${timeoutMs}ms; skipped`,
      output: scrubber.scrub(res.stderr || res.stdout),
      durationMs: res.durationMs,
    };
  }

  if (isBinaryMissingOutput(res.exitCode, res.stderr)) {
    return {
      level: 'L1',
      tool,
      passed: true,
      exitCode: null,
      skipped: true,
      summary: `${tool} not installed on host; skipped`,
      output: '',
      durationMs: res.durationMs,
    };
  }

  const combined = scrubber.scrub([res.stdout, res.stderr].filter(Boolean).join('\n').trim());
  const passed = res.exitCode === 0;
  return {
    level: 'L1',
    tool,
    passed,
    exitCode: res.exitCode,
    skipped: false,
    summary: passed ? `${tool} passed` : `${tool} failed (exit ${res.exitCode ?? 'null'})`,
    output: combined,
    durationMs: res.durationMs || Date.now() - startedAt,
  };
}

function resolveFileContent(
  workspaceDir: string,
  relPath: string,
  fileContents?: Record<string, string>,
): string | null {
  if (fileContents && relPath in fileContents) {
    return fileContents[relPath]!;
  }
  const abs = path.resolve(workspaceDir, relPath);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
    return null;
  }
  return fs.readFileSync(abs, 'utf8');
}

/**
 * Runs the 3-layer adaptive static validation pipeline (L0 -> L1 -> L2).
 */
export async function runValidationPipeline(
  options: ValidationPipelineOptions,
): Promise<ValidationPipelineResult> {
  const pipelineStart = Date.now();
  const syncBudgetMs = options.syncBudgetMs ?? 2800;
  const l1BudgetMs = Math.min(options.l1BudgetMs ?? 2500, syncBudgetMs);
  const scrubber = options.scrubber ?? createSecretScrubber();

  const steps: ValidationStepResult[] = [];
  const filesToCheck: FileContentInput[] = [];

  for (const rel of options.changedFiles) {
    const content = resolveFileContent(options.workspaceDir, rel, options.fileContents);
    if (content !== null) {
      filesToCheck.push({ path: rel, content });
    }
  }

  // L0: Always runs in-process
  const l0 = await runL0Preflight(filesToCheck, {
    allowPlaceholderMarkers: options.allowPlaceholderMarkers,
    scrubber,
  });
  steps.push(l0.step);

  let highestLevelRun: ValidationLevel | null = 'L0';

  // L1: Adaptive fast linter routing
  if (!options.skipL1 && filesToCheck.length > 0) {
    const l1Targets = options.changedFiles.filter((rel) =>
      fs.existsSync(path.resolve(options.workspaceDir, rel)),
    );

    if (l1Targets.length > 0) {
      const remainingBudget = () =>
        Math.max(0, l1BudgetMs - (Date.now() - pipelineStart));

      const biomeFiles = l1Targets.filter((f) =>
        ['.ts', '.tsx', '.js', '.jsx', '.json', '.css'].includes(path.extname(f).toLowerCase()),
      );
      const pyFiles = l1Targets.filter((f) => path.extname(f).toLowerCase() === '.py');
      const goFiles = l1Targets.filter((f) => path.extname(f).toLowerCase() === '.go');
      const shFiles = l1Targets.filter((f) =>
        ['.sh', '.bash'].includes(path.extname(f).toLowerCase()),
      );
      const dockerFiles = l1Targets.filter((f) => {
        const base = path.basename(f);
        return base === 'Dockerfile' || base.startsWith('Dockerfile.');
      });
      const yamlFiles = l1Targets.filter((f) =>
        ['.yml', '.yaml'].includes(path.extname(f).toLowerCase()),
      );
      const workflowYamlFiles = yamlFiles.filter((f) =>
        f.replace(/\\/g, '/').includes('.github/workflows/'),
      );
      const tfFiles = l1Targets.filter((f) => path.extname(f).toLowerCase() === '.tf');
      const wranglerFiles = l1Targets.filter((f) => {
        const base = path.basename(f).toLowerCase();
        return base === 'wrangler.toml' || base === 'wrangler.jsonc';
      });

      const runPlanned = async (tool: string, cmd: string, args: string[]) => {
        const budget = remainingBudget();
        const step = await runLinterStep(
          options.workspaceDir,
          tool,
          cmd,
          args,
          budget,
          scrubber,
        );
        steps.push(step);
        if (!step.skipped) {
          highestLevelRun = 'L1';
        }
      };

      if (biomeFiles.length > 0) {
        await runPlanned('biome', 'biome', ['check', ...biomeFiles]);
      }
      if (
        options.runHeavyChecks &&
        biomeFiles.some((f) => ['.ts', '.tsx'].includes(path.extname(f).toLowerCase())) &&
        fs.existsSync(path.join(options.workspaceDir, 'tsconfig.json'))
      ) {
        await runPlanned('tsc', 'tsc', ['--noEmit', '--incremental']);
      }
      if (pyFiles.length > 0) {
        await runPlanned('ruff', 'ruff', ['check', ...pyFiles]);
        if (options.runHeavyChecks) {
          await runPlanned('pyright', 'pyright', pyFiles);
        }
      }
      if (goFiles.length > 0) {
        await runPlanned('gofmt', 'gofmt', ['-e', ...goFiles]);
        await runPlanned('go-vet', 'go', ['vet', './...']);
      }
      if (wranglerFiles.length > 0 && options.runHeavyChecks) {
        await runPlanned('wrangler-dry-run', 'wrangler', ['deploy', '--dry-run']);
      }
      if (shFiles.length > 0) {
        await runPlanned('shellcheck', 'shellcheck', shFiles);
      }
      if (dockerFiles.length > 0) {
        await runPlanned('hadolint', 'hadolint', dockerFiles);
      }
      if (yamlFiles.length > 0) {
        await runPlanned('yamllint', 'yamllint', yamlFiles);
      }
      if (workflowYamlFiles.length > 0) {
        await runPlanned('actionlint', 'actionlint', workflowYamlFiles);
      }
      if (tfFiles.length > 0) {
        await runPlanned('tofu-fmt', 'tofu', ['fmt', '-check', ...tfFiles]);
      }
    }
  }

  // L2: Non-blocking test hint
  if (!options.skipL2) {
    const { stack } = detectWorkspaceStackAndPlaybook(options.workspaceDir);
    const suggested = [...stack.testCommands, ...stack.typecheckCommands];
    if (suggested.length > 0) {
      steps.push({
        level: 'L2',
        tool: 'test-hint',
        passed: true,
        exitCode: null,
        skipped: true,
        summary: `Suggested verification via workspace_exec: ${suggested.join(' && ')}`,
        output: '',
        durationMs: 0,
      });
      if (highestLevelRun === null) {
        highestLevelRun = 'L2';
      }
    }
  }

  const passed = steps.every((s) => s.passed);
  const failedSteps = steps.filter((s) => !s.passed);
  const summary = passed
    ? `Validation passed (${steps.map((s) => `${s.level}:${s.tool}${s.skipped ? '[skipped]' : ''}`).join(', ')})`
    : `Validation failed at ${failedSteps.map((s) => `${s.level}:${s.tool}`).join(', ')}`;

  return {
    passed,
    highestLevelRun,
    steps,
    summary,
    diagnostics: l0.diagnostics,
  };
}
