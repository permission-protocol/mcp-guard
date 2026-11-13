/**
 * secret_read: reading or printing credentials. Covers
 *   - file readers (cat, head, grep, cp, base64, curl @file, `< file`, ...) on secret
 *     files: .env*, ~/.aws/credentials, SSH private keys, .netrc, .pgpass, kubeconfig,
 *     docker config, gcloud credentials, keychains, *.pem / *.key / *.p12;
 *   - environment dumps: printenv, env, set, export -p, declare -p, /proc/<pid>/environ;
 *   - echo/printf of variables named like secrets ($AWS_SECRET_ACCESS_KEY, $GITHUB_TOKEN);
 *   - token printers and secret-store reads: gcloud auth print-access-token, aws
 *     secretsmanager get-secret-value, az account get-access-token, gh auth token,
 *     vault read / kv get, op read, security find-generic-password, kubectl get secret -o,
 *     doppler secrets, heroku config, railway variables, vercel env pull, git credential fill.
 * A bare path (a file argument rather than a command) that names a secret file also matches.
 *
 * Pure. No I/O.
 */
import { overShell } from './combine.js';
import { hasFlag, positionals, DYN, type Cmd, type Word } from './shell.js';
import { found, type DetectorResult } from './types.js';

const READERS = new Set([
  'cat', 'tac', 'less', 'more', 'head', 'tail', 'bat', 'batcat', 'nl', 'strings', 'xxd', 'hexdump', 'od', 'base64', 'base32',
  'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'awk', 'gawk', 'mawk', 'sed', 'sort', 'uniq', 'cut', 'jq', 'yq', 'cp', 'scp',
  'rsync', 'tar', 'zip', 'gzip', 'openssl', 'curl', 'wget', 'nc', 'ncat', 'dd', 'diff', 'cmp', 'xclip', 'pbcopy', 'tee', 'paste',
  'column', 'fold', 'rev', 'iconv', 'vim', 'vi', 'nano', 'view', 'gpg', 'ssh-keygen', 'install', 'ln', 'mv',
]);

const ENV_EXAMPLE = /\.(example|sample|template|dist|defaults?|schema)$/i;
const SECRET_VAR = /(SECRET|TOKEN|PASSWORD|PASSWD|_PASS$|^PASS$|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|AUTH|_KEY$|DSN|DATABASE_URL)/i;

/** True when a path names a file that holds credentials. */
export function isSecretPath(raw: string): boolean {
  const p = raw.replace(/^@/, '').replace(/^(file|of|if)=/, '');
  if (!p || p.includes(DYN)) return false;
  const lower = p.toLowerCase();
  const base = lower.split('/').pop() ?? lower;
  if ((/^\.env(\..+)?$/.test(base) || /\.env$/.test(base)) && !ENV_EXAMPLE.test(base)) return true;
  if (/(^|\/)\.aws\/(credentials|sso\/cache)/.test(lower)) return true;
  if (/^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$/.test(base)) return true;
  if (/(^|\/)\.ssh\//.test(lower) && !/\.pub$/.test(base) && !['known_hosts', 'known_hosts.old', 'config', 'authorized_keys', 'authorized_keys2'].includes(base)) return true;
  if (['.netrc', '_netrc', '.pgpass', '.git-credentials', '.npmrc', '.pypirc', '.vault-token', 'credentials.db', 'access_tokens.db', 'application_default_credentials.json', 'legacy_credentials', 'credentials.json', 'secrets.json', 'secrets.yaml', 'secrets.yml'].includes(base)) return true;
  if (/(^|\/)\.docker\/config\.json$/.test(lower) || /(^|\/)\.kube\/config$/.test(lower) || /(^|\/)\.config\/gh\/hosts\.yml$/.test(lower) || /(^|\/)\.config\/gcloud\//.test(lower) || /(^|\/)\.azure\//.test(lower)) return true;
  if (/\.(pem|key|p12|pfx|jks|keystore|keychain|keychain-db|kdbx|ovpn)$/.test(base)) return true;
  if (/^\/proc\/[^/]+\/environ$/.test(lower)) return true;
  return false;
}

function fileRead(cmd: Cmd): DetectorResult | null {
  for (const r of cmd.redirects) {
    if ((r.op === '<' || r.op === '<>') && r.target && isSecretPath(r.target.text)) return found(kindOf(r.target.text), r.target.text);
  }
  if (!READERS.has(cmd.name)) return null;
  for (const w of cmd.args) {
    const texts = [w.text, ...w.text.split('=').slice(1), ...(w.text.includes('@') ? [w.text.slice(w.text.indexOf('@') + 1)] : [])];
    for (const t of texts) if (isSecretPath(t)) return found(kindOf(t), t);
  }
  return null;
}

const kindOf = (p: string): string => (/\/proc\/[^/]+\/environ$/.test(p) ? 'env_dump' : 'secret_file');

function envDump(cmd: Cmd): DetectorResult | null {
  const pos = positionals(cmd.args);
  switch (cmd.name) {
    case 'printenv':
      if (!pos.length) return found('env_dump');
      return pos.some((w) => SECRET_VAR.test(w.text)) ? found('secret_env', pos.find((w) => SECRET_VAR.test(w.text))!.text) : null;
    case 'env':
      return pos.length === 0 ? found('env_dump') : null;
    case 'set':
      return cmd.args.length === 0 ? found('env_dump') : null;
    case 'export':
      return cmd.args.length === 0 || (cmd.args.every((w) => w.text === '-p')) ? found('env_dump') : null;
    case 'declare':
    case 'typeset':
      return pos.length === 0 && cmd.args.some((w) => /^-[a-zA-Z]*[px]/.test(w.text)) ? found('env_dump') : null;
    case 'echo':
    case 'printf':
    case 'print': {
      const v = cmd.args.flatMap((w) => w.vars).find((name) => SECRET_VAR.test(name));
      return v ? found('secret_env', v) : null;
    }
    default:
      return null;
  }
}

function tokenOrStore(cmd: Cmd): DetectorResult | null {
  const t = positionals(cmd.args).map((w: Word) => w.text.toLowerCase());
  const has = (...xs: string[]): boolean => xs.every((x) => t.includes(x));
  switch (cmd.name) {
    case 'gcloud':
      if (t.some((x) => x === 'print-access-token' || x === 'print-identity-token' || x === 'config-helper')) return found('cloud_token');
      if (has('secrets', 'versions', 'access')) return found('secret_store', t[t.indexOf('access') + 1]);
      return null;
    case 'aws':
      if (has('secretsmanager', 'get-secret-value')) return found('secret_store');
      if (has('ssm') && t.some((x) => x.startsWith('get-parameter')) && hasFlag(cmd.args, '--with-decryption')) return found('secret_store');
      if (has('configure', 'export-credentials')) return found('cloud_token');
      if (has('configure', 'get') && t.some((x) => /secret|key|token/.test(x))) return found('cloud_token');
      if (has('ecr', 'get-login-password')) return found('cloud_token');
      if (has('kms', 'decrypt')) return found('secret_store');
      return null;
    case 'az':
      if (has('get-access-token')) return found('cloud_token');
      if (has('keyvault', 'secret') && t.some((x) => x === 'show' || x === 'download')) return found('secret_store');
      if (has('keys', 'list')) return found('cloud_token');
      return null;
    case 'gh':
      if (has('auth', 'token')) return found('cloud_token');
      if (has('auth', 'status') && (hasFlag(cmd.args, '--show-token') || hasFlag(cmd.args, '-t'))) return found('cloud_token');
      return null;
    case 'vault':
      if (t[0] === 'read' || (t[0] === 'kv' && (t[1] === 'get' || t[1] === 'read')) || has('print', 'token')) return found('secret_store', t[t.length - 1]);
      return null;
    case 'op':
      if (t[0] === 'read' || t[0] === 'inject' || (t[0] === 'item' && t[1] === 'get') || (t[0] === 'document' && t[1] === 'get')) return found('secret_store');
      return null;
    case 'security':
      if (t.some((x) => /^(find-generic-password|find-internet-password|dump-keychain|export)$/.test(x))) return found('keychain');
      return null;
    case 'secret-tool':
      return t[0] === 'lookup' ? found('keychain') : null;
    case 'pass':
      if (!t.length) return null;
      if (t[0] === 'show' || !['init', 'ls', 'list', 'find', 'search', 'insert', 'add', 'edit', 'generate', 'rm', 'remove', 'mv', 'cp', 'git', 'grep', 'help', 'version'].includes(t[0])) return found('secret_store', t[t.length - 1]);
      return null;
    case 'kubectl':
    case 'oc': {
      const g = t.indexOf('get');
      if (g < 0) return null;
      const types = (t[g + 1] ?? '').split(',').map((x) => x.split('/')[0]);
      const secret = types.some((x) => x === 'secret' || x === 'secrets') || t.slice(g + 1).some((x) => x.startsWith('secret/') || x.startsWith('secrets/'));
      const output = cmd.args.some((w) => w.text === '-o' || w.text.startsWith('-o') || w.text.startsWith('--output'));
      return secret && output ? found('secret_store', t[g + 2]) : null;
    }
    case 'doppler':
      return t[0] === 'secrets' ? found('secret_store') : null;
    case 'heroku':
      return t[0] === 'config' || t[0] === 'config:get' ? found('secret_store') : null;
    case 'railway':
      return t[0] === 'variables' || t[0] === 'vars' || t[0] === 'variable' ? found('secret_store') : null;
    case 'vercel':
      return has('env', 'pull') ? found('secret_store') : null;
    case 'git':
      return has('credential', 'fill') ? found('cloud_token') : null;
    default:
      return null;
  }
}

function check(cmd: Cmd, all: Cmd[]): DetectorResult | null {
  // A bare path (a file argument, not a command).
  if (all.length === 1 && cmd.args.length === 0 && !cmd.redirects.length && isSecretPath(cmd.path)) {
    return found(kindOf(cmd.path), cmd.path);
  }
  return fileRead(cmd) ?? envDump(cmd) ?? tokenOrStore(cmd);
}

export function secretRead(text: string): DetectorResult {
  return overShell(text, check);
}
