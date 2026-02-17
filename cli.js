#!/usr/bin/env node
/**
 * BYBOB CLI - Unified command-line interface
 * 
 * Usage:
 *   bybob monitor <chain> [--no-llm] [--output <dir>]
 *   bybob scan <address> --chain <chain> [--output <dir>]
 *   bybob scan <bytecode-file> [--output <dir>]
 */

require('dotenv').config();
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const COMMANDS = {
  monitor: 'Monitor a chain for new contract deployments',
  scan: 'Scan a specific address or bytecode file',
  help: 'Show this help message'
};

const CHAINS = ['eth', 'bsc', 'base', 'arb', 'op', 'polygon', 'hyper'];

function printHelp() {
  console.log(`
\x1b[1mBYOCB ArbInjectionSkill\x1b[0m
Smart contract vulnerability scanner for arbitrary call injection

\x1b[1mUSAGE:\x1b[0m
  arb-injection <command> [options]

\x1b[1mCOMMANDS:\x1b[0m
  monitor <chain>              Monitor chain for new deployments
  scan <address> --chain <c>   Scan a deployed contract
  scan <file>                  Scan bytecode from file
  help                         Show this help

\x1b[1mCHAINS:\x1b[0m
  ${CHAINS.join(', ')}

\x1b[1mOPTIONS:\x1b[0m
  --no-llm       Disable LLM deep analysis (faster, no API cost)
  --output <dir> Save results to specified directory
  --chain <c>    Specify chain for address scanning

\x1b[1mEXAMPLES:\x1b[0m
  arb-injection monitor bsc                    # Monitor BSC mainnet
  arb-injection monitor eth --no-llm           # Monitor Ethereum, no LLM
  arb-injection scan 0x1234... --chain base    # Scan address on Base
  arb-injection scan ./bytecode.txt            # Scan local bytecode file

\x1b[1mENVIRONMENT:\x1b[0m
  ANTHROPIC_API_KEY    Required for LLM analysis (optional)
  BYBOB_OUTPUT         Default output directory (optional)
`);
}

function runCommand(script, args) {
  const scriptPath = path.join(__dirname, script);
  const child = spawn(process.execPath, [scriptPath, ...args], {
    stdio: 'inherit',
    env: process.env
  });
  
  child.on('close', (code) => {
    process.exit(code || 0);
  });
}

function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const restArgs = args.slice(1);

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    process.exit(0);
  }

  // Handle output directory override
  const outputIdx = restArgs.indexOf('--output');
  if (outputIdx !== -1 && restArgs[outputIdx + 1]) {
    process.env.BYBOB_OUTPUT = restArgs[outputIdx + 1];
    restArgs.splice(outputIdx, 2);
  }

  switch (command) {
    case 'monitor':
      const chain = restArgs[0];
      if (!chain || !CHAINS.includes(chain)) {
        console.error(`Error: Invalid chain. Use one of: ${CHAINS.join(', ')}`);
        process.exit(1);
      }
      runCommand('index.js', restArgs);
      break;

    case 'scan':
      const target = restArgs[0];
      if (!target) {
        console.error('Error: Specify an address or bytecode file');
        process.exit(1);
      }
      
      // Check if it's an address (needs --chain) or file
      if (target.match(/^0x[0-9a-fA-F]{40}$/)) {
        const chainIdx = restArgs.indexOf('--chain');
        if (chainIdx === -1 || !restArgs[chainIdx + 1]) {
          console.error('Error: --chain required when scanning an address');
          process.exit(1);
        }
        const scanChain = restArgs[chainIdx + 1];
        runCommand('modules/scan-arbitrary-call.js', [target, '--rpc', scanChain]);
      } else if (fs.existsSync(target)) {
        runCommand('modules/scan-arbitrary-call.js', [target]);
      } else {
        console.error('Error: Target must be a valid address (0x...) or existing file');
        process.exit(1);
      }
      break;

    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

main();
