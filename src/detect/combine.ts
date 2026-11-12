import { analyzeShell, type Cmd } from './shell.js';
import { NOT_MATCHED, unparseable, type DetectorResult } from './types.js';

/**
 * Run a per-command check over shell text. A definite finding wins; otherwise any
 * command the check could not read, or any reader problem, fails safe as a match.
 */
export function overShell(text: string, check: (cmd: Cmd, all: Cmd[]) => DetectorResult | null): DetectorResult {
  const { cmds, problem } = analyzeShell(text);
  let uncertain: DetectorResult | null = null;
  for (const cmd of cmds) {
    const r = check(cmd, cmds);
    if (!r || !r.matched) continue;
    if (r.parsed) return r;
    uncertain ??= r;
  }
  if (uncertain) return uncertain;
  if (problem) return unparseable(problem);
  return NOT_MATCHED;
}
