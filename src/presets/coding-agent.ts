/**
 * The `coding-agent` preset: a ready policy for Claude Code, Cursor, Codex and other
 * coding agents. See docs/presets.md for what it holds, observes and misses.
 *
 * Every rule is `require_approval` or observe-only, so no rule can let a call through
 * that a later rule would have held: the order only decides which rule id a hold names.
 */

export const PRESET_NAMES = ['coding-agent'] as const;
export type PresetName = (typeof PRESET_NAMES)[number];

export function isPresetName(v: unknown): v is PresetName {
  return typeof v === 'string' && (PRESET_NAMES as readonly string[]).includes(v);
}

/** Argument names coding agents and shell MCP servers use for a command (a string, or an argv list). */
export const SHELL_ARGS = ['command', 'cmd', 'commands', 'script', 'shell_command', 'bash_command'] as const;
/** Argument names database MCP servers use for SQL. */
export const SQL_ARGS = ['sql', 'query', 'statement', 'statements', 'sql_query'] as const;
/** Argument names file tools use for a path. */
export const PATH_ARGS = ['path', 'file_path', 'target_file', 'notebook_path', 'filename', 'source', 'destination'] as const;
/** File tools that write, edit, move or delete the file at their path argument. */
export const WRITE_TOOLS = ['Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'write_file', 'edit_file', 'edit_block', 'move_file', 'delete_file'] as const;

const list = (xs: readonly string[]): string => `[${xs.join(', ')}]`;

/** Arguments a production target can appear in: commands, SQL, and connection / project / context arguments. */
const TARGET_ARGS = [...SHELL_ARGS.filter((a) => a !== 'commands'), 'sql', 'query', 'statement', 'database', 'host', 'connection_string', 'project_id', 'context', 'namespace', 'branch'];

/** Codex's apply_patch names each file it touches on a `*** Update File:` / `*** Delete File:` / `*** Move to:` line. */
const PATCH_GUARD_PATTERN =
  '\\*\\*\\* (Add File|Update File|Delete File|Move to): [^\\n]*(pp\\.config\\.ya?ml|receipts\\.jsonl|mcp-guard/(keys|policies|install-token)|\\.mcp\\.json|\\.claude\\.json|claude_desktop_config\\.json|\\.cursor/mcp\\.json|\\.vscode/mcp\\.json|\\.claude/settings(\\.local)?\\.json|\\.codex/config\\.toml|\\.gemini/settings\\.json)';

/**
 * The preset's policy body: everything but `server_label` and `cloud:`, which `init`
 * adds. Loads on its own (local-only holds).
 */
export function codingAgentPolicyBody(): string {
  const shell = list(SHELL_ARGS);
  const lines = [
    '# Preset: coding-agent (mcp-guard init --preset coding-agent). See docs/presets.md.',
    '# Destructive commands wait for a named human. Secret reads are only recorded (observe: true)',
    '# until you remove that line. Rules are tried in order; the first match wins.',
    'default_action: allow',
    'mode: enforce',
    '',
    '# What counts as production. List literal names (no patterns); quote account ids.',
    '# A call whose command, SQL or connection arguments name one waits for a signature.',
    'targets:',
    '  databases: []        # e.g. [prod-db.internal, app_production]',
    '  cloud_accounts: []   # e.g. [acme-prod, "123456789012"]',
    '  kube_contexts: []    # e.g. [prod-eu-1, production]',
    '  git_branches: []     # e.g. [release]  (pushes to main/master are already held)',
    '',
    'rules:',
    '  # Self-protection: the agent may read the guard\'s files, not change them or stop the guard.',
    `  - { id: guard-tamper, tool: "*", detect: { detector: guard_tamper, args: ${shell} }, action: require_approval }`,
    ...WRITE_TOOLS.map((t) => `  - { id: guard-tamper-${t.toLowerCase()}, tool: ${t}, detect: { detector: guard_tamper, args: ${list(PATH_ARGS)} }, action: require_approval }`),
    `  - id: guard-tamper-apply-patch`,
    `    tool: apply_patch`,
    `    match: { input: { pattern: ${JSON.stringify(PATCH_GUARD_PATTERN)}, ignore_case: true } }`,
    `    action: require_approval`,
    '',
    '  # Data destruction: enforced from day one.',
    `  - { id: destructive-sql, tool: "*", detect: { detector: sql_destructive, args: ${list(SQL_ARGS)} }, action: require_approval }`,
    `  - { id: destructive-shell, tool: "*", detect: { detector: shell_destructive, args: ${shell} }, action: require_approval }`,
    `  - { id: terraform-destroy, tool: "*", detect: { detector: terraform_destroy, args: ${shell} }, action: require_approval }`,
    `  - { id: cloud-delete, tool: "*", detect: { detector: cloud_delete, args: ${shell} }, action: require_approval }`,
    '',
    '  # Production: holds any call that names a target listed above. Matches nothing while the lists are empty.',
    `  - { id: production-target, tool: "*", mentions_target: { args: ${list(TARGET_ARGS)} }, action: require_approval }`,
    '',
    '  # Secret reads: recorded as "would hold", not enforced. Delete `observe: true` to enforce.',
    `  - { id: secret-read, tool: "*", detect: { detector: secret_read, args: ${list([...SHELL_ARGS, 'path', 'file_path', 'target_file'])} }, action: require_approval, observe: true }`,
  ];
  return lines.join('\n') + '\n';
}

export function presetPolicyBody(name: PresetName): string {
  switch (name) {
    case 'coding-agent':
      return codingAgentPolicyBody();
  }
}
