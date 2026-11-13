import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';

const BIN = join(__dirname, '..', '..', '..', 'bin', 'mcp-guard');

/**
 * A stand-in `npx` first on PATH: records its arguments and runs this build. Tests use it
 * wherever init would start `npx -y @permission-protocol/mcp-guard@<version>`, so they
 * never reach the npm registry and do not depend on this version being published.
 */
export function fakeNpx(root: string): { env: NodeJS.ProcessEnv; log: string; bin: string } {
  const bin = join(root, 'fake-bin');
  mkdirSync(bin, { recursive: true });
  const log = join(root, 'npx.log');
  writeFileSync(join(bin, 'npx'), `#!/bin/sh\necho "$*" >> ${JSON.stringify(log)}\ncase "$1" in -y|--no-install) shift;; esac\nshift\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(BIN)} "$@"\n`);
  chmodSync(join(bin, 'npx'), 0o755);
  return { env: { PATH: `${bin}${delimiter}${process.env.PATH}` }, log, bin };
}
