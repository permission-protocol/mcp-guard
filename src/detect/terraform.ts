/**
 * terraform_destroy: `terraform destroy`, `terraform apply -destroy`, `apply` of a plan
 * made with `plan -destroy` in the same text, and `apply -auto-approve` without a saved
 * plan (a plan nobody saw). The same for `tofu` / `opentofu`, and `terragrunt` (including
 * run-all). `TF_CLI_ARGS*` assignments are read as extra arguments.
 *
 * Pure. No I/O.
 */
import { overShell } from './combine.js';
import { type Cmd, type Word } from './shell.js';
import { found, unparseable, type DetectorResult } from './types.js';

const TOOLS = new Set(['terraform', 'tofu', 'opentofu', 'terragrunt']);
const VALUE_FLAGS = /^-(var|var-file|target|replace|state|state-out|backup|lock-timeout|parallelism|out|chdir)$/;

function extraArgs(cmd: Cmd): { words: string[]; dynamic: boolean } {
  const words: string[] = [];
  let dynamic = false;
  for (const a of cmd.assigns) {
    if (!/^TF_CLI_ARGS/.test(a.text)) continue;
    if (a.dynamic) dynamic = true;
    words.push(...a.text.slice(a.text.indexOf('=') + 1).split(/\s+/).filter(Boolean));
  }
  return { words, dynamic };
}

function check(cmd: Cmd, all: Cmd[]): DetectorResult | null {
  if (!TOOLS.has(cmd.name)) return null;
  const extra = extraArgs(cmd);
  if (extra.dynamic) return unparseable('dynamic_argument', 'terraform');
  const args: Word[] = cmd.args;
  const flags = [...args.map((w) => w.text), ...extra.words].filter((t) => t.startsWith('-')).map((t) => t.replace(/^--/, '-'));
  const pos: Word[] = [];
  for (let k = 0; k < args.length; k++) {
    const t = args[k].text;
    if (t.startsWith('-')) {
      if (VALUE_FLAGS.test(t.replace(/^--/, '-'))) k++;
      continue;
    }
    pos.push(args[k]);
  }
  const subs = cmd.name === 'terragrunt' ? pos.filter((w) => !w.dynamic).map((w) => w.text) : pos.slice(0, 1).map((w) => w.text);
  if (pos.slice(0, 2).some((w) => w.dynamic)) return unparseable('dynamic_argument', 'terraform');
  const has = (f: string): boolean => flags.some((x) => x === f || x.startsWith(f + '='));
  const target = flags.find((f) => f.startsWith('-target='))?.slice('-target='.length);

  if (subs.includes('destroy')) return found('destroy', target);
  if (!subs.includes('apply')) return null;
  if (has('-destroy') && !flags.includes('-destroy=false')) return found('apply_destroy', target);
  const planFile = cmd.name === 'terragrunt' ? undefined : pos[1];
  if (planFile) {
    // A plan made with -destroy earlier in the same text.
    const destroyPlan = all.some((c) => TOOLS.has(c.name) && c.args[0]?.text === 'plan' && c.args.some((w) => w.text === '-destroy' || w.text === '--destroy'));
    if (destroyPlan) return found('apply_destroy', target);
    return null;
  }
  if (has('-auto-approve') && !flags.includes('-auto-approve=false')) return found('apply_auto_approve', target);
  return null;
}

export function terraformDestroy(text: string): DetectorResult {
  return overShell(text, check);
}
