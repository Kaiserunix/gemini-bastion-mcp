import type {
  AgentRunOptions,
  AgentRunResult,
  AgentRunner,
  JobEvent,
  ScrubberLike,
  TokenUsage,
} from '../../types.js';
import { buildSandboxedEnv } from '../../utils/exec.js';
import {
  assertSafeCliFlagValue,
  runCliAgentDriver,
  type CliDriverDeps,
  type CliDriverSpec,
  type ParsedCliLineResult,
} from './baseCliDriver.js';

export function buildOpenCodeEnv(
  config: CliDriverDeps['config'],
  baseEnv: Record<string, string | undefined> = process.env,
): Record<string, string> {
  const env = buildSandboxedEnv({ baseEnv });
  if (config.anthropicApiKey) {
    env.ANTHROPIC_API_KEY = config.anthropicApiKey;
  }
  if (config.geminiApiKey) {
    env.GEMINI_API_KEY = config.geminiApiKey;
  }
  if (config.openaiApiKey || config.codexApiKey) {
    env.OPENAI_API_KEY = config.openaiApiKey ?? config.codexApiKey!;
  }
  if (config.codexBaseUrl) {
    env.OPENAI_BASE_URL = config.codexBaseUrl;
  }
  return env;
}

const openCodeSpec: CliDriverSpec = {
  driver: 'opencode',
  runnerName: 'OpenCodeCliRunner',
  defaultBinary: 'opencode',
  allowNetwork: true,

  buildArgs(options: AgentRunOptions): string[] {
    const args = ['run', '--format', 'json'];
    if (options.resumeThreadId) {
      args.push('--session', assertSafeCliFlagValue('resumeThreadId', options.resumeThreadId));
    }
    if (options.model) {
      args.push('--model', assertSafeCliFlagValue('model', options.model));
    }
    args.push('--', options.objective);
    return args;
  },

  buildEnv: buildOpenCodeEnv,

  parseJsonLine(
    parsed: Record<string, unknown>,
    scrubber: ScrubberLike,
  ): ParsedCliLineResult {
    const ts = Date.now();
    const events: Array<Omit<JobEvent, 'seq'>> = [];
    const threadId =
      typeof parsed.sessionID === 'string' && parsed.sessionID
        ? parsed.sessionID
        : typeof parsed.session_id === 'string' && parsed.session_id
          ? parsed.session_id
          : typeof parsed.thread_id === 'string' && parsed.thread_id
            ? parsed.thread_id
            : undefined;

    const eventType = typeof parsed.type === 'string' ? parsed.type : '';
    const part = parsed.part as Record<string, unknown> | undefined;
    let finalReportText: string | undefined;
    let tokenUsage: TokenUsage | undefined;
    let errorMessage: string | undefined;

    if (eventType === 'step_start' && threadId) {
      events.push({
        ts,
        type: 'status',
        message: `OpenCode session step started: ${threadId}`,
        data: { session_id: threadId },
      });
    } else if (eventType === 'text') {
      const textVal =
        typeof part?.text === 'string'
          ? part.text
          : typeof parsed.text === 'string'
            ? parsed.text
            : '';
      if (textVal) {
        const clean = scrubber.scrub(textVal);
        finalReportText = clean;
        events.push({
          ts,
          type: 'agent_message',
          message: clean.slice(0, 2000),
        });
      }
    } else if (eventType === 'tool_use') {
      const toolName =
        typeof part?.tool === 'string'
          ? part.tool
          : typeof parsed.tool === 'string'
            ? parsed.tool
            : 'tool';
      events.push({
        ts,
        type: 'tool_call',
        message: scrubber.scrub(`opencode.tool_use: ${toolName}`),
      });
    } else if (eventType === 'step_finish') {
      const tokens = (part?.tokens ?? parsed.tokens) as Record<string, unknown> | undefined;
      if (tokens && typeof tokens === 'object') {
        const input = Number(tokens.input ?? tokens.input_tokens ?? 0) || 0;
        const output = Number(tokens.output ?? tokens.output_tokens ?? 0) || 0;
        const cacheObj = tokens.cache as { read?: unknown } | undefined;
        const cached = Number(cacheObj?.read ?? tokens.cached_input_tokens ?? 0) || 0;
        const total = input + output;
        tokenUsage = {
          input_tokens: input,
          cached_input_tokens: cached,
          output_tokens: output,
          total_tokens: total,
        };
        events.push({
          ts,
          type: 'token_usage',
          message: `OpenCode step finished (input=${input}, output=${output}, total=${total})`,
          data: { ...tokenUsage },
        });
      }
    } else if (eventType === 'error') {
      const errObj = parsed.error as { message?: unknown; data?: { message?: unknown } } | undefined;
      const rawErr =
        typeof errObj?.data?.message === 'string'
          ? errObj.data.message
          : typeof errObj?.message === 'string'
            ? errObj.message
            : typeof parsed.message === 'string'
              ? parsed.message
              : 'OpenCode error';
      errorMessage = scrubber.scrub(rawErr);
      events.push({ ts, type: 'error', message: errorMessage });
    }

    return {
      threadId,
      events,
      finalReportText,
      tokenUsage,
      errorMessage,
    };
  },
};

export class OpenCodeCliRunner implements AgentRunner {
  readonly name = 'opencode-cli';

  constructor(private readonly deps: CliDriverDeps) {}

  async run(options: AgentRunOptions): Promise<AgentRunResult> {
    return runCliAgentDriver(openCodeSpec, this.deps, options);
  }
}
