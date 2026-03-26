import { loadConfig } from './config.js';
import { startProxy } from './proxy.js';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

export function main(): void {
  const args = process.argv.slice(2);

  if (args[0] === 'demo') {
    // When running via npx @permission-protocol/mcp-guard demo
    const scriptPath = join(__dirname, '../../example/test.sh');
    const result = spawnSync('bash', [scriptPath], { stdio: 'inherit' });
    process.exit(result.status ?? 0);
  }

  let configPath = './pp.config.yaml';
  let agentId = 'unknown';
  let modeOverride: 'enforce' | 'observe' | undefined;
  let approvalPort: number | undefined;
  let serverCommand: string[] = [];

  const dashDashIndex = args.indexOf('--');
  const cliArgs = dashDashIndex >= 0 ? args.slice(0, dashDashIndex) : args;
  serverCommand = dashDashIndex >= 0 ? args.slice(dashDashIndex + 1) : [];

  for (let i = 0; i < cliArgs.length; i++) {
    if (cliArgs[i] === '--config' && cliArgs[i + 1]) {
      configPath = cliArgs[++i];
    } else if (cliArgs[i] === '--agent-id' && cliArgs[i + 1]) {
      agentId = cliArgs[++i];
    } else if (cliArgs[i] === '--mode' && cliArgs[i + 1]) {
      const m = cliArgs[++i];
      if (m === 'enforce' || m === 'observe') modeOverride = m;
    } else if (cliArgs[i] === '--approval-port' && cliArgs[i + 1]) {
      approvalPort = parseInt(cliArgs[++i], 10);
      if (isNaN(approvalPort)) {
        process.stderr.write('[mcp-guard] Error: --approval-port must be a number\n');
        process.exit(1);
      }
    } else if (cliArgs[i] === '--help' || cliArgs[i] === '-h') {
      printHelp();
      process.exit(0);
    }
  }

  if (serverCommand.length === 0) {
    process.stderr.write('[mcp-guard] Error: No server command. Use: mcp-guard [options] -- <server command>\n');
    process.exit(1);
  }

  const config = loadConfig(configPath);
  if (modeOverride) config.mode = modeOverride;
  process.stderr.write(`[mcp-guard] Loaded ${config.rules.length} rules (default: ${config.default_action}, mode: ${config.mode})\n`);
  process.stderr.write(`[mcp-guard] Starting server: ${serverCommand.join(' ')}\n`);

  startProxy(config, agentId, serverCommand, approvalPort);
}

function printHelp(): void {
  const help = `
mcp-guard — MCP tool-call policy proxy

Usage:
  mcp-guard [options] -- <server command>

Options:
  --config <path>         Path to config file (default: ./pp.config.yaml)
  --agent-id <id>         Agent identifier for receipts (default: "unknown")
  --mode <mode>           enforce or observe (overrides config; default: enforce)
  --approval-port <port>  Enable approval UI on this port (e.g. 3100)
  -h, --help              Show this help

Example:
  mcp-guard --config pp.config.yaml -- node my-mcp-server.js

  # With approval UI:
  mcp-guard --config pp.config.yaml --approval-port 3100 -- node my-mcp-server.js
`.trim();
  console.log(help);
}

main();
