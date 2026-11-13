import { analyzeShell, type Cmd } from './shell.js';
import { NOT_MATCHED, unparseable, type DetectorResult } from './types.js';

/**
 * Run a per-command check over shell text. A definite finding wins; otherwise any
 * command the check could not read, or any reader problem, fails safe as a match.
 * With `rank`, the definite finding shown is the highest ranked (ties: the first), so
 * `git push -f origin x && rm -rf /` shows the `rm`. Ranking chooses only what is shown:
 * whether the text matches is the same either way.
 */
export function overShell(text: string, check: (cmd: Cmd, all: Cmd[]) => DetectorResult | null, rank?: (r: DetectorResult) => number): DetectorResult {
  const { cmds, problem } = analyzeShell(text);
  let uncertain: DetectorResult | null = null;
  let best: DetectorResult | null = null;
  for (const cmd of cmds) {
    const r = check(cmd, cmds);
    if (!r || !r.matched) continue;
    if (r.parsed) {
      if (!rank) return r;
      if (!best || rank(r) > rank(best)) best = r;
      continue;
    }
    uncertain ??= r;
  }
  if (best) return best;
  if (uncertain) return uncertain;
  if (problem) return unparseable(problem);
  return NOT_MATCHED;
}
