/**
 * Coding-agent hook adapters. An adapter turns one hook event (the agent's own payload)
 * into the engine's `(toolName, args)` shape, and turns a verdict back into the answer
 * that agent's hook contract expects. It decides nothing: the decision path
 * (hook/decide.ts) is the same for every agent. Adding Cursor or Codex means adding an
 * adapter here, not touching the decision path.
 */

/** A built-in tool call, in the shape the policy engine evaluates. */
export interface HookCall {
  /** The agent's own tool name (`Bash`, `Write`, ...). Policy rules name it in `tool:`. */
  tool: string;
  /** What the policy reads and the fingerprint covers. */
  args: Record<string, unknown>;
}

/**
 * What the hook answers:
 *   allow  a verified, redeemed, human-signed receipt released the call
 *   pass   the policy allowed it: no opinion, the agent's own permission flow still runs
 *   deny   refused; `reason` names rule ids, detector kinds and codes, never argument text
 */
export type HookVerdict =
  | {
      kind: 'allow';
      reason: string;
      /** For the agent: Claude Code adds it to Claude's context (`additionalContext`). On an allow, `reason` reaches only the debug log. */
      context?: string;
      /** For the person: shown in the session (`systemMessage`). */
      notice?: string;
    }
  | { kind: 'pass' }
  | { kind: 'deny'; reason: string; notice?: string };

export interface HookAnswer {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export class HookInputError extends Error {
  constructor(readonly code: 'HOOK_INPUT_MALFORMED' | 'HOOK_EVENT_UNSUPPORTED', message: string) {
    super(message);
    this.name = 'HookInputError';
  }
}

export interface HookAdapter {
  /** Adapter name, as given to `mcp-guard hook --agent`. */
  readonly name: string;
  /** Server label for receipts and fingerprints: the agent, since there is no MCP server. */
  readonly serverLabel: string;
  /** Agent id recorded on receipts. */
  readonly agentId: string;
  /** Parse one event. Throws HookInputError on anything it cannot read. */
  parse(raw: string): HookCall;
  answer(verdict: HookVerdict): HookAnswer;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Tool names the guard passes to the engine and the API: same charset the cloud path enforces. */
const TOOL_NAME = /^[A-Za-z0-9_.:/@-]{1,128}$/;

/**
 * Claude Code tools whose input carries fields that do not change what runs (the
 * model's own description, a time limit). They are left out of what the policy reads
 * and what the signer approves, so a retried call keeps its fingerprint. Every other
 * tool's input is used as it arrives.
 */
const SHELL_TOOLS = new Set(['Bash', 'PowerShell']);

/**
 * Claude Code PreToolUse (https://code.claude.com/docs/en/hooks, verified 2026-11-12;
 * see docs/hooks.md). stdin carries `hook_event_name`, `tool_name`, `tool_input`. The
 * answer is JSON on stdout under `hookSpecificOutput`; a deny also exits 2 with the
 * reason on stderr, which blocks the call even if the JSON were unreadable.
 */
export const claudeCodeAdapter: HookAdapter = {
  name: 'claude-code',
  serverLabel: 'claude-code',
  agentId: 'claude-code',

  parse(raw: string): HookCall {
    let event: unknown;
    try {
      event = JSON.parse(raw);
    } catch {
      throw new HookInputError('HOOK_INPUT_MALFORMED', 'the hook event on stdin is not JSON');
    }
    if (!isRecord(event)) throw new HookInputError('HOOK_INPUT_MALFORMED', 'the hook event on stdin is not a JSON object');
    if (event.hook_event_name !== 'PreToolUse') {
      throw new HookInputError('HOOK_EVENT_UNSUPPORTED', 'mcp-guard hook answers PreToolUse events only');
    }
    const tool = event.tool_name;
    if (typeof tool !== 'string' || !TOOL_NAME.test(tool)) {
      throw new HookInputError('HOOK_INPUT_MALFORMED', 'the hook event has no usable tool_name');
    }
    const input = event.tool_input;
    if (!isRecord(input)) throw new HookInputError('HOOK_INPUT_MALFORMED', 'the hook event has no tool_input object');

    if (SHELL_TOOLS.has(tool)) {
      // The command text lands in `command`, the argument the shell detectors scan.
      // A missing or non-string command is passed as-is: rules and detectors fail safe on it.
      return { tool, args: input.command === undefined ? {} : { command: input.command } };
    }
    return { tool, args: { ...input } };
  },

  answer(verdict: HookVerdict): HookAnswer {
    if (verdict.kind === 'pass') return { stdout: '', stderr: '', exitCode: 0 };
    // `permissionDecisionReason` reaches Claude on a deny and only the debug log on an
    // allow; `additionalContext` reaches Claude; `systemMessage` is shown to the person.
    const out = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: verdict.kind,
        permissionDecisionReason: verdict.reason,
        ...(verdict.kind === 'allow' && verdict.context ? { additionalContext: verdict.context } : {}),
      },
      ...(verdict.notice ? { systemMessage: verdict.notice } : {}),
    };
    const stdout = JSON.stringify(out) + '\n';
    if (verdict.kind === 'allow') return { stdout, stderr: '', exitCode: 0 };
    // Exit 2 blocks the call whatever happens to stdout; stderr is then the reason Claude sees.
    return { stdout, stderr: verdict.reason + '\n', exitCode: 2 };
  },
};

export const ADAPTERS: Record<string, HookAdapter> = { [claudeCodeAdapter.name]: claudeCodeAdapter };
