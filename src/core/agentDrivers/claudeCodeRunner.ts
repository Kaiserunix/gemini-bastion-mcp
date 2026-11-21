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

export function buildClaudeCodeEnv(
  config: CliDriverDeps['config'],
  baseEnv: Record<string, string | undefined> = process.env,
): Record<string, string> {
  const env = buildSandboxedEnv({ baseEnv });
  if (config.anthropicApiKey) {
    env.ANTHROPIC_API_KEY = config.anthropicApiKey;
  }
  return env;
}

const claudeCodeSpec: CliDriverSpec = {
  driver: 'claude_code',
  runnerName: 'ClaudeCodeCliRunner',
  defaultBinary: 'claude',
  allowNetwork: true,

  buildArgs(options: AgentRunOptions): string[] {
    const args = [
      '-p',
      '--output-format',
      'stream-json',
      '--verbose',
      '--permission-mode',
      options.mode === 'write' ? 'acceptEdits' : 'plan',
    ];
    if (options.resumeThreadId) {
      args.push('--resume', assertSafeCliFlagValue('resumeThreadId', options.resumeThreadId));
    }
    if (options.model) {
      args.push('--model', assertSafeCliFlagValue('model', options.model));
    }
    args.push('--', options.objective);
    return args;
  },

  buildEnv: buildClaudeCodeEnv,

  parseJsonLine(
    parsed: Record<string, unknown>,
    scrubber: ScrubberLike,
  ): ParsedCliLineResult {
    const ts = Date.now();
    const events: Array<Omit<JobEvent, 'seq'>> = [];
    const threadId =
      typeof parsed.session_id === 'string' && parsed.session_id
        ? parsed.session_id
        : undefined;

    const eventType = typeof parsed.type === 'string' ? parsed.type : '';
    let finalReportText: string | undefined;
    let tokenUsage: TokenUsage | undefined;
    let errorMessage: string | undefined;

    if (eventType === 'system' && parsed.subtype === 'init' && threadId) {
      events.push({
        ts,
        type: 'status',
        message: `Claude Code session started: ${threadId}`,
        data: { session_id: threadId },
      });
    } else if (eventType === 'assistant') {
      const msg = parsed.message as { content?: unknown } | undefined;
      const blocks = Array.isArray(msg?.content) ? msg.content : [];
      const textParts: string[] = [];
      for (const block of blocks) {
        if (!block || typeof block !== 'object') continue;
        const b = block as Record<string, unknown>;
        if (b.type === 'text' && typeof b.text === 'string') {
          textParts.push(b.text);
        } else if (b.type === 'tool_use' && typeof b.name === 'string') {
          events.push({
            ts,
            type: 'tool_call',
            message: scrubber.scrub(`claude.tool_use: ${b.name}`),
          });
        }
      }
      if (textParts.length > 0) {
        const cleanText = scrubber.scrub(textParts.join('\n'));
        finalReportText = cleanText;
        events.push({
          ts,
          type: 'agent_message',
          message: cleanText.slice(0, 2000),
        });
      }
    } else if (eventType === 'result') {
      if (typeof parsed.result === 'string' && parsed.result.length > 0) {
        finalReportText = scrubber.scrub(parsed.result);
      }
      const usageObj = parsed.usage as Record<string, unknown> | undefined;
      if (usageObj && typeof usageObj === 'object') {
        const input = Number(usageObj.input_tokens ?? 0) || 0;
        const cached = Number(usageObj.cache_read_input_tokens ?? 0) || 0;
        const output = Number(usageObj.output_tokens ?? 0) || 0;
        tokenUsage = {
          input_tokens: input,
          cached_input_tokens: cached,
          output_tokens: output,
          total_tokens: input + output,
        };
        events.push({
          ts,
          type: 'token_usage',
          message: `Claude Code completed (input=${input}, output=${output}, total=${input + output})`,
          data: { ...tokenUsage },
        });
      }
      if (parsed.is_error === true) {
        errorMessage = scrubber.scrub(
          typeof parsed.result === 'string' ? parsed.result : 'Claude Code reported an error',
        );
        events.push({
          ts,
          type: 'error',
          message: errorMessage,
        });
      }
    } else if (eventType === 'error') {
      const errObj = parsed.error as { message?: unknown } | undefined;
      const rawErr =
        typeof errObj?.message === 'string'
          ? errObj.message
          : typeof parsed.message === 'string'
            ? parsed.message
            : 'Claude Code error';
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

export class ClaudeCodeCliRunner implements AgentRunner {
  readonly name = 'claude-code-cli';

  constructor(private readonly deps: CliDriverDeps) {}

  async run(options: AgentRunOptions): Promise<AgentRunResult> {
    return runCliAgentDriver(claudeCodeSpec, this.deps, options);
  }
}
