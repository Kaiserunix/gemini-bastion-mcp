import type { JobRepository } from '../../db/repositories/jobRepo.js';
import type { WorkspaceRepository } from '../../db/repositories/workspaceRepo.js';
import type {
  AgentDriverName,
  AgentRunOptions,
  AgentRunResult,
  AgentRunner,
  GatewayConfig,
  ScrubberLike,
} from '../../types.js';
import { createSecretScrubber } from '../../utils/secretScrubber.js';
import { CodexSdkRunner } from '../codexRunner.js';
import {
  workspaceLockManager,
  type WorkspaceLockManager,
} from '../workspaceLock.js';
import { ClaudeCodeCliRunner, buildClaudeCodeEnv } from './claudeCodeRunner.js';
import { GeminiCliRunner, buildGeminiCliEnv } from './geminiCliRunner.js';
import { OpenCodeCliRunner, buildOpenCodeEnv } from './openCodeRunner.js';
import { RemoteSidecarAgentRunner } from './remoteSidecarRunner.js';
import type { SubprocessStarter } from './baseCliDriver.js';

export { ClaudeCodeCliRunner, buildClaudeCodeEnv } from './claudeCodeRunner.js';
export { GeminiCliRunner, buildGeminiCliEnv } from './geminiCliRunner.js';
export { OpenCodeCliRunner, buildOpenCodeEnv } from './openCodeRunner.js';
export { RemoteSidecarAgentRunner, type RemoteSidecarRunnerDeps } from './remoteSidecarRunner.js';
export type { CliDriverDeps, SubprocessStarter } from './baseCliDriver.js';

export interface AgentRunnerRegistryDeps {
  config: GatewayConfig;
  jobRepo?: JobRepository;
  workspaceRepo?: WorkspaceRepository;
  lockManager?: WorkspaceLockManager;
  scrubber?: ScrubberLike;
  codexRunner?: AgentRunner;
  runners?: Partial<Record<AgentDriverName, AgentRunner>>;
  remoteRunner?: AgentRunner;
  useRemoteSidecar?: boolean;
  subprocessStarter?: SubprocessStarter;
  fetchImpl?: typeof fetch;
}

/**
 * Multi-driver AgentRunner router supporting `codex`, `claude_code`, `gemini_cli`, `opencode`,
 * and transparent delegation to an isolated-runner sidecar when `AGENT_RUNNER_URL` is configured.
 */
export class AgentRunnerRegistry implements AgentRunner {
  readonly name = 'agent-runner-registry';

  private readonly defaultDriver: AgentDriverName;
  private readonly runners: Record<AgentDriverName, AgentRunner>;
  private readonly remoteRunner?: AgentRunner;

  constructor(deps: AgentRunnerRegistryDeps) {
    const scrubber = deps.scrubber ?? createSecretScrubber(deps.config);
    const lockManager = deps.lockManager ?? workspaceLockManager;
    this.defaultDriver = deps.config.defaultAgentDriver ?? 'codex';

    const sharedDriverDeps = {
      config: deps.config,
      jobRepo: deps.jobRepo,
      workspaceRepo: deps.workspaceRepo,
      lockManager,
      scrubber,
      subprocessStarter: deps.subprocessStarter,
    };

    const codexRunner =
      deps.codexRunner ??
      deps.runners?.codex ??
      new CodexSdkRunner({
        config: deps.config,
        jobRepo: deps.jobRepo,
        workspaceRepo: deps.workspaceRepo,
        lockManager,
        scrubber,
      });

    this.runners = {
      codex: codexRunner,
      claude_code: deps.runners?.claude_code ?? new ClaudeCodeCliRunner(sharedDriverDeps),
      gemini_cli: deps.runners?.gemini_cli ?? new GeminiCliRunner(sharedDriverDeps),
      opencode: deps.runners?.opencode ?? new OpenCodeCliRunner(sharedDriverDeps),
    };

    if (deps.remoteRunner) {
      this.remoteRunner = deps.remoteRunner;
    } else if (deps.useRemoteSidecar !== false && deps.config.agentRunnerUrl) {
      this.remoteRunner = new RemoteSidecarAgentRunner({
        config: deps.config,
        jobRepo: deps.jobRepo,
        workspaceRepo: deps.workspaceRepo,
        lockManager,
        scrubber,
        fetchImpl: deps.fetchImpl,
      });
    }
  }

  getRunner(driver?: AgentDriverName): AgentRunner {
    if (this.remoteRunner) {
      return this.remoteRunner;
    }
    const resolved = driver ?? this.defaultDriver;
    const runner = this.runners[resolved];
    if (!runner) {
      throw new Error(`Unsupported agent driver "${String(resolved)}"`);
    }
    return runner;
  }

  async run(options: AgentRunOptions): Promise<AgentRunResult> {
    const resolvedDriver = options.driver ?? this.defaultDriver;
    const runner = this.getRunner(resolvedDriver);
    return runner.run({
      ...options,
      driver: resolvedDriver,
    });
  }
}

export function createAgentRunnerRegistry(deps: AgentRunnerRegistryDeps): AgentRunner {
  return new AgentRunnerRegistry(deps);
}
