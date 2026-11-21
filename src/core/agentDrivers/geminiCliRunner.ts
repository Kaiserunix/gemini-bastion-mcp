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

export function buildGeminiCliEnv(
  config: CliDriverDeps['config'],
  baseEnv: Record<string, string | undefined> = process.env,
): Record<string, string> {
  const env = buildSandboxedEnv({ baseEnv });
  if (config.geminiApiKey) {
    env.GEMINI_API_KEY = config.geminiApiKey;
  }
  return env;
}

const geminiCliSpec: CliDriverSpec = {
  driver: 'gemini_cli',
  runnerName: 'GeminiCliRunner',
  defaultBinary: 'gemini',
  allowNetwork: true,

  buildArgs(options: AgentRunOptions): string[] {
    const args = [
      `--prompt=${options.objective}`,
      '--output-format',
      'stream-json',
      '--approval-mode',
      options.mode === 'write' ? 'yolo' : 'plan',
    ];
    if (options.resumeThreadId) {
      args.push('--resume', assertSafeCliFlagValue('resumeThreadId', options.resumeThreadId));
    }
    if (options.model) {
      args.push('-m', assertSafeCliFlagValue('model', options.model));
    }
    return args;
  },

  buildEnv: buildGeminiCliEnv,

  parseJsonLine(
    parsed: Record<string, unknown>,
    scrubber: ScrubberLike,
  ): ParsedCliLineResult {
    const ts = Date.now();
    const events: Array<Omit<JobEvent, 'seq'>> = [];
    const threadId =
      typeof parsed.session_id === 'string' && parsed.session_id
        ? parsed.session_id
        : typeof parsed.thread_id === 'string' && parsed.thread_id
          ? parsed.thread_id
          : undefined;

    const eventType = typeof parsed.type === 'string' ? parsed.type : '';
    let finalReportText: string | undefined;
    let tokenUsage: TokenUsage | undefined;
    let errorMessage: string | undefined;

    if (eventType === 'init' && threadId) {
      events.push({
        ts,
        type: 'status',
        message: `Gemini CLI session started: ${threadId}`,
        data: { session_id: threadId },
      });
    } else if (eventType === 'message') {
      const role = typeof parsed.role === 'string' ? parsed.role : 'assistant';
      const content = typeof parsed.content === 'string' ? parsed.content : '';
      if (role !== 'user' && content) {
        const clean = scrubber.scrub(content);
        finalReportText = clean;
        events.push({
          ts,
          type: 'agent_message',
          message: clean.slice(0, 2000),
        });
      }
    } else if (eventType === 'tool_use' || eventType === 'tool_result') {
      const toolName =
        typeof parsed.tool_name === 'string'
          ? parsed.tool_name
          : typeof parsed.name === 'string'
            ? parsed.name
            : 'tool';
      events.push({
        ts,
        type: 'tool_call',
        message: scrubber.scrub(`gemini.${eventType}: ${toolName}`),
      });
    } else if (eventType === 'result') {
      if (typeof parsed.response === 'string' && parsed.response.length > 0) {
        finalReportText = scrubber.scrub(parsed.response);
      }
      const stats = parsed.stats as Record<string, unknown> | undefined;
      const tokens = (stats?.tokens ?? parsed.usage) as Record<string, unknown> | undefined;
      if (tokens && typeof tokens === 'object') {
        const input = Number(tokens.input_tokens ?? tokens.input ?? 0) || 0;
        const cached = Number(tokens.cached ?? tokens.cached_input_tokens ?? 0) || 0;
        const output = Number(tokens.output_tokens ?? tokens.output ?? 0) || 0;
        const total = Number(tokens.total_tokens ?? tokens.total ?? input + output) || input + output;
        tokenUsage = {
          input_tokens: input,
          cached_input_tokens: cached,
          output_tokens: output,
          total_tokens: total,
        };
        events.push({
          ts,
          type: 'token_usage',
          message: `Gemini CLI completed (input=${input}, output=${output}, total=${total})`,
          data: { ...tokenUsage },
        });
      }
      if (parsed.status === 'error') {
        const errObj = parsed.error as { message?: unknown } | undefined;
        errorMessage = scrubber.scrub(
          typeof errObj?.message === 'string' ? errObj.message : 'Gemini CLI reported an error',
        );
        events.push({ ts, type: 'error', message: errorMessage });
      }
    } else if (eventType === 'error') {
      const rawErr =
        typeof parsed.message === 'string'
          ? parsed.message
          : typeof (parsed.error as { message?: unknown } | undefined)?.message === 'string'
            ? String((parsed.error as { message?: unknown }).message)
            : 'Gemini CLI error';
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

export class GeminiCliRunner implements AgentRunner {
  readonly name = 'gemini-cli';

  constructor(private readonly deps: CliDriverDeps) {}

  async run(options: AgentRunOptions): Promise<AgentRunResult> {
    return runCliAgentDriver(geminiCliSpec, this.deps, options);
  }
}
