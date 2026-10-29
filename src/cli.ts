import { loadConfig } from './config.js';
import { startProxy } from './proxy.js';
import { runVerify } from './verify-cli.js';
import { exportPublicKey, currentKeyId, keysDir } from './signer.js';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

export function main(): void {
  const args = process.argv.slice(2);

  if (args[0] === 'demo') {
    // When running via npx @permission-protocol/mcp-guard demo
    const scriptPath = join(__dirname, '../../example/test.sh');
    const result = spawnSync('bash', [scriptPath], { stdio: 'inherit' });
    process.exit(result.status ?? 0);
  }

  if (args[0] === 'verify') {
    process.exit(runVerify(args.slice(1)));
  }

  if (args[0] === 'export-key') {
    // Write the signing public key (the trust anchor verifiers pin). Never the private key.
    const out = args[1] || 'mcp-guard.pub.pem';
    exportPublicKey(out);
    console.log(`Wrote public key ${currentKeyId()} to ${out} (private key stays in ${keysDir()})`);
    process.exit(0);
  }

  let configPath = './pp.config.yaml';
  let agentId = 'unknown';
  let modeOverride: 'enforce' | 'observe' | undefined;
  let approvalPort: number | undefined;
  let operator: string | undefined;

  const dashDashIndex = args.indexOf('--');
  const cliArgs = dashDashIndex >= 0 ? args.slice(0, dashDashIndex) : args;
  const serverCommand = dashDashIndex >= 0 ? args.slice(dashDashIndex + 1) : [];

  for (let i = 0; i < cliArgs.length; i++) {
    if (cliArgs[i] === '--config' && cliArgs[i + 1]) {
      configPath = cliArgs[++i];
    } else if (cliArgs[i] === '--agent-id' && cliArgs[i + 1]) {
      agentId = cliArgs[++i];
    } else if (cliArgs[i] === '--operator' && cliArgs[i + 1]) {
      operator = cliArgs[++i];
    } else if (cliArgs[i] === '--mode' && cliArgs[i + 1]) {
      const m = cliArgs[++i];
      if (m !== 'enforce' && m !== 'observe') {
        process.stderr.write('[mcp-guard] Error: --mode must be enforce or observe\n');
        process.exit(1);
      }
      modeOverride = m;
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

  let config;
  try {
    config = loadConfig(configPath);
  } catch (err: any) {
    process.stderr.write(`[mcp-guard] Error: ${err.message}\n`);
    process.exit(1);
  }
  if (modeOverride) config.mode = modeOverride;
  process.stderr.write(`[mcp-guard] Loaded ${config.rules.length} rules (default: ${config.default_action}, mode: ${config.mode})\n`);
  if (config.default_action === 'allow') {
    process.stderr.write('[mcp-guard] WARNING: default_action is "allow" — any tool or method without a rule runs unchecked. Use "block" or "require_approval" to fail closed.\n');
  }
  process.stderr.write(`[mcp-guard] Starting server: ${serverCommand[0]}\n`);

  try {
    startProxy(config, agentId, serverCommand, { approvalPort, operator });
  } catch (err: any) {
    process.stderr.write(`[mcp-guard] Error: ${err.message}\n`);
    process.exit(1);
  }
}

function printHelp(): void {
  const help = `
mcp-guard — MCP policy proxy

Usage:
  mcp-guard [options] -- <server command>
  mcp-guard verify --receipt-file <path> --keys <keys.json> [--trust ID=sha256:<hex>] --scope s [--scope-ref r] [--scope-sha h]
  mcp-guard verify --receipt-file <legacy 0.2 receipt> --pubkey <pem> --scope s ...
  mcp-guard export-key [out.pem]

Options:
  --config <path>         Path to config file (default: ./pp.config.yaml)
  --agent-id <id>         Agent identifier for receipts (default: "unknown")
  --operator <name>       Approver name recorded on receipts (default: OS username)
  --mode <mode>           enforce or observe (overrides config; default: enforce)
  --approval-port <port>  Enable the approval UI on 127.0.0.1:<port>
  -h, --help              Show this help

The approval UI URL printed at startup carries its access token after "#t=".
Open that exact URL; requests without the token are refused.

Example:
  mcp-guard --config pp.config.yaml --approval-port 3100 -- node my-mcp-server.js
`.trim();
  console.log(help);
}

main();
