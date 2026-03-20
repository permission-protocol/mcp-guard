import { loadConfig } from './config.js';
import { startProxy } from './proxy.js';

export function main(): void {
  const args = process.argv.slice(2);

  let configPath = './pp.config.yaml';
  let agentId = 'unknown';
  let modeOverride: 'enforce' | 'observe' | undefined;
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

  startProxy(config, agentId, serverCommand);
}

function printHelp(): void {
  const help = `
mcp-guard — MCP tool-call policy proxy

Usage:
  mcp-guard [options] -- <server command>

Options:
  --config <path>     Path to config file (default: ./pp.config.yaml)
  --agent-id <id>     Agent identifier for receipts (default: "unknown")
  --mode <mode>       enforce or observe (overrides config; default: enforce)
  -h, --help          Show this help

Example:
  mcp-guard --config pp.config.yaml -- node my-mcp-server.js
`.trim();
  console.log(help);
}

main();
