import { statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, resolve } from 'node:path';
import { keysDir } from './keystore.js';

/**
 * Where a detached or long-lived child of the guard starts: the guard's own config
 * directory (the key directory's parent, `~/.config/mcp-guard` by default), else the
 * home directory. Never the project the agent works in: on Windows a process whose
 * working directory is a folder keeps that folder from being deleted or renamed.
 */
export function neutralCwd(deps: { configDir?: string; home?: string; isDir?: (path: string) => boolean } = {}): string {
  const isDir = deps.isDir ?? ((path: string): boolean => { try { return statSync(path).isDirectory(); } catch { return false; } });
  let configDir: string | null = null;
  try { configDir = resolve(deps.configDir ?? dirname(keysDir())); } catch { configDir = null; }
  if (configDir && isDir(configDir)) return configDir;
  return deps.home ?? homedir();
}

/** Path variables the guard reads. A child started in another directory gets them as absolute paths, so it reads the same files. */
const PATH_VARS = ['PP_KEYS_DIR', 'XDG_CONFIG_HOME', 'PP_SHARED_RECEIPTS_PATH', 'PP_HOOK_STATE_PATH'] as const;

/** `env` with the guard's own path variables made absolute against this process's working directory. */
export function childEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...env };
  for (const name of PATH_VARS) {
    const value = out[name];
    if (value && !isAbsolute(value)) out[name] = resolve(value);
  }
  return out;
}
