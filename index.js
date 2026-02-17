#!/usr/bin/env node
/**
 * BYBOB - Bytecode Observer Bot
 * Monitors new blocks for contract deployments and scans for arbitrary call injection
 */

require('dotenv').config();
const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');
const { BytecodeScanner } = require('./modules/scan-arbitrary-call');
const { analyzeContract, shouldAnalyze } = require('./modules/llm-analyzer');

// Version check on startup
async function checkForUpdates() {
  try {
    const pkg = require('./package.json');
    const res = await fetch('https://registry.npmjs.org/byocb-arb-injection/latest', {
      signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) return;
    const { version: latest } = await res.json();
    if (latest !== pkg.version) {
      const [latestMajor] = latest.split('.').map(Number);
      const [currentMajor] = pkg.version.split('.').map(Number);
      if (latestMajor > currentMajor) {
        console.log(`\n\x1b[31m🚨 Breaking update available: ${pkg.version} → ${latest}\x1b[0m`);
        console.log(`   Run: npm update -g byocb-arb-injection\n`);
      } else {
        console.log(`\n\x1b[33m⚠️  Update available: ${pkg.version} → ${latest}\x1b[0m`);
        console.log(`   Run: npm update -g byocb-arb-injection\n`);
      }
    }
  } catch {
    // Silent fail - don't block startup
  }
}

// Results directory: BYBOB_OUTPUT env var or default to ./results
const RESULTS_DIR = process.env.BYBOB_OUTPUT || path.join(__dirname, 'results');

const RPC_ENDPOINTS = {
  eth: 'https://eth.llamarpc.com',
  bsc: 'https://bsc-rpc.publicnode.com',
  base: 'https://mainnet.base.org',
  arb: 'https://arb1.arbitrum.io/rpc',
  op: 'https://mainnet.optimism.io',
  polygon: 'https://polygon-rpc.com',
  hyper: 'https://rpc.hypurrscan.io'
};

class ContractMonitor {
  constructor(chain = 'bsc', options = {}) {
    this.chain = chain;
    this.rpcUrl = RPC_ENDPOINTS[chain];
    this.provider = null;
    this.stats = { blocks: 0, contracts: 0, flagged: 0, llmAnalyzed: 0 };
    this.useLLM = options.llm !== false;
    this.llmQueue = [];
    this.processingLLM = false;
  }

  log(msg, type = 'info') {
    const time = new Date().toISOString().slice(11, 19);
    const colors = { info: '\x1b[36m', warn: '\x1b[33m', error: '\x1b[31m', success: '\x1b[32m', critical: '\x1b[35m' };
    console.log(`${colors[type] || ''}[${time}]\x1b[0m ${msg}`);
  }

  async connect() {
    this.log(`Connecting to ${this.chain.toUpperCase()}...`);
    this.provider = new ethers.JsonRpcProvider(this.rpcUrl);
    const blockNum = await this.provider.getBlockNumber();
    this.log(`Connected at block ${blockNum}`, 'success');
    return this;
  }

  async getContractCreations(blockNumber) {
    const block = await this.provider.getBlock(blockNumber, true);
    if (!block || !block.prefetchedTransactions) return [];

    const creations = [];

    for (const tx of block.prefetchedTransactions) {
      if (tx.to === null) {
        try {
          const receipt = await this.provider.getTransactionReceipt(tx.hash);
          if (receipt && receipt.contractAddress) {
            creations.push({
              address: receipt.contractAddress,
              deployer: tx.from,
              txHash: tx.hash,
              blockNumber,
            });
          }
        } catch (e) {}
      }
    }

    return creations;
  }

  async scanContract(address) {
    try {
      const code = await this.provider.getCode(address);
      if (!code || code === '0x' || code.length < 10) {
        return null;
      }

      const scanner = new BytecodeScanner(code);
      const results = scanner.scan(true);
      const verdict = scanner.getVerdict(results);

      return { code, results, verdict };
    } catch (e) {
      this.log(`Scan failed ${address}: ${e.message}`, 'error');
      return null;
    }
  }

  formatFindings(contract, scan) {
    const { address, deployer, txHash } = contract;
    const { verdict, results } = scan;

    let output = '\n' + '='.repeat(80) + '\n';
    output += `\x1b[1m[${verdict}] NEW CONTRACT DEPLOYED\x1b[0m\n`;
    output += '='.repeat(80) + '\n';
    output += `Address:  ${address}\n`;
    output += `Deployer: ${deployer}\n`;
    output += `TX:       ${txHash}\n`;
    output += `Chain:    ${this.chain.toUpperCase()}\n`;
    output += `Size:     ${(scan.code.length - 2) / 2} bytes\n`;
    output += '\n--- Static Analysis ---\n';
    output += `Access Control: ${results.accessControl.type}\n`;
    output += `CALL: ${results.stats.calls} | DELEGATECALL: ${results.stats.delegatecalls}\n`;
    output += `Protected: ${results.accessControl.protectedCalls} | Unprotected: ${results.accessControl.unprotectedCalls}\n`;

    if (results.indicators.length > 0) {
      output += '\n--- Risk Indicators ---\n';
      for (const ind of results.indicators) {
        output += `[${ind.risk}] ${ind.msg}\n`;
      }
    }

    output += '='.repeat(80) + '\n';
    return output;
  }

  saveFinding(contract, scan, llmAnalysis = null) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const shortAddr = contract.address.slice(0, 10);
    const filename = `${this.chain}_${shortAddr}_${timestamp}`;

    if (!fs.existsSync(RESULTS_DIR)) {
      fs.mkdirSync(RESULTS_DIR, { recursive: true });
    }

    const jsonData = {
      timestamp: new Date().toISOString(),
      chain: this.chain,
      contract: {
        address: contract.address,
        deployer: contract.deployer,
        txHash: contract.txHash,
        blockNumber: contract.blockNumber
      },
      staticAnalysis: {
        verdict: scan.verdict,
        bytecodeSize: (scan.code.length - 2) / 2,
        accessControl: scan.results.accessControl,
        stats: scan.results.stats,
        indicators: scan.results.indicators,
        selectors: scan.results.selectors
      },
      llmAnalysis: llmAnalysis ? {
        success: llmAnalysis.success,
        analysis: llmAnalysis.analysis,
        tokens: llmAnalysis.tokens
      } : null,
      bytecode: scan.code
    };

    fs.writeFileSync(path.join(RESULTS_DIR, `${filename}.json`), JSON.stringify(jsonData, null, 2));

    // Markdown report
    let md = `# Vulnerability Report: ${contract.address}\n\n`;
    md += `**Chain:** ${this.chain.toUpperCase()}\n`;
    md += `**Verdict:** ${scan.verdict}\n`;
    md += `**Timestamp:** ${new Date().toISOString()}\n\n`;
    md += `## Contract Details\n\n`;
    md += `- **Address:** \`${contract.address}\`\n`;
    md += `- **Deployer:** \`${contract.deployer}\`\n`;
    md += `- **TX Hash:** \`${contract.txHash}\`\n`;
    md += `- **Block:** ${contract.blockNumber}\n`;
    md += `- **Bytecode Size:** ${(scan.code.length - 2) / 2} bytes\n\n`;
    md += `## Static Analysis\n\n`;
    md += `- **Access Control:** ${scan.results.accessControl.type}\n`;
    md += `- **CALL:** ${scan.results.stats.calls} | **DELEGATECALL:** ${scan.results.stats.delegatecalls}\n`;
    md += `- **Protected:** ${scan.results.accessControl.protectedCalls} | **Unprotected:** ${scan.results.accessControl.unprotectedCalls}\n\n`;

    if (scan.results.indicators.length > 0) {
      md += `### Risk Indicators\n\n`;
      for (const ind of scan.results.indicators) {
        md += `- **[${ind.risk}]** ${ind.msg}\n`;
      }
      md += '\n';
    }

    if (llmAnalysis && llmAnalysis.success) {
      md += `## LLM Deep Analysis\n\n`;
      md += llmAnalysis.analysis + '\n\n';
    }

    md += `## Bytecode\n\n\`\`\`\n${scan.code.slice(0, 2000)}${scan.code.length > 2000 ? '\n...' : ''}\n\`\`\`\n`;

    fs.writeFileSync(path.join(RESULTS_DIR, `${filename}.md`), md);

    this.log(`Saved: ${filename}`, 'success');
    return filename;
  }

  queueForLLM(contract, scan) {
    this.llmQueue.push({ contract, scan });
    this.processLLMQueue();
  }

  async processLLMQueue() {
    if (this.processingLLM || this.llmQueue.length === 0) return;

    this.processingLLM = true;

    while (this.llmQueue.length > 0) {
      const { contract, scan } = this.llmQueue.shift();

      this.log(`LLM analyzing ${contract.address.slice(0, 10)}...`, 'info');

      let llmResult = null;
      try {
        llmResult = await analyzeContract({
          address: contract.address,
          bytecode: scan.code,
          chain: this.chain,
          deployer: contract.deployer,
          scanResults: { verdict: scan.verdict, results: scan.results }
        });

        this.stats.llmAnalyzed++;

        if (llmResult.success) {
          console.log('\n' + '─'.repeat(80));
          console.log('\x1b[35m[LLM ANALYSIS]\x1b[0m', contract.address);
          console.log('─'.repeat(80));
          console.log(llmResult.analysis);
          console.log('─'.repeat(80) + '\n');

          if (llmResult.tokens) {
            this.log(`Tokens: ${llmResult.tokens.input_tokens} in / ${llmResult.tokens.output_tokens} out`, 'info');
          }
        } else {
          this.log(`LLM failed: ${llmResult.analysis}`, 'error');
        }
      } catch (e) {
        this.log(`LLM error: ${e.message}`, 'error');
      }

      this.saveFinding(contract, scan, llmResult);

      if (this.llmQueue.length > 0) {
        await new Promise(r => setTimeout(r, 1000));
      }
    }

    this.processingLLM = false;
  }

  async processBlock(blockNumber) {
    this.stats.blocks++;

    const contracts = await this.getContractCreations(blockNumber);
    if (contracts.length === 0) return;

    this.log(`Block ${blockNumber}: ${contracts.length} contract(s)`);

    for (const contract of contracts) {
      this.stats.contracts++;

      const scan = await this.scanContract(contract.address);
      if (!scan) continue;

      const { verdict } = scan;

      if (verdict === 'CRITICAL' || verdict === 'HIGH') {
        this.stats.flagged++;
        console.log(this.formatFindings(contract, scan));

        if (this.useLLM && shouldAnalyze({ verdict, results: scan.results })) {
          this.queueForLLM(contract, scan);
        } else {
          this.saveFinding(contract, scan, null);
        }
      } else {
        this.log(`${contract.address}... [${verdict}]`, verdict === 'MEDIUM' ? 'warn' : 'info');
      }
    }
  }

  async start() {
    await this.connect();

    // Subscribe to new blocks
    this.provider.on('block', async (blockNumber) => {
      try {
        await this.processBlock(blockNumber);
      } catch (e) {
        this.log(`Block ${blockNumber} error: ${e.message}`, 'error');
      }
    });

    this.log('Subscribed to new blocks', 'success');
    console.log('');

    // Stats every minute
    setInterval(() => {
      if (this.stats.blocks > 0) {
        const llmInfo = this.useLLM ? ` | ${this.stats.llmAnalyzed} LLM` : '';
        this.log(`Stats: ${this.stats.blocks} blocks | ${this.stats.contracts} contracts | ${this.stats.flagged} flagged${llmInfo}`, 'info');
      }
    }, 60000);
  }
}

// CLI
const args = process.argv.slice(2);
const chain = args.find(a => !a.startsWith('--')) || 'bsc';
const noLLM = args.includes('--no-llm');

if (!RPC_ENDPOINTS[chain]) {
  console.log(`
\x1b[1mBYOCB ArbInjectionSkill\x1b[0m

Usage: node index.js <chain> [options]

Chains: ${Object.keys(RPC_ENDPOINTS).join(', ')}

Options:
  --no-llm    Disable LLM deep analysis

Example:
  node index.js bsc           # Monitor BSC with LLM
  node index.js eth --no-llm  # Monitor Ethereum without LLM
`);
  process.exit(1);
}

const llmStatus = noLLM ? 'disabled' : (process.env.ANTHROPIC_API_KEY ? 'enabled' : 'disabled (no API key)');

console.log(`
\x1b[1m╔══════════════════════════════════════════════════════════════╗
║  BYOCB ArbInjectionSkill                                      ║
║  Monitoring for arbitrary call injection vulnerabilities      ║
╚══════════════════════════════════════════════════════════════╝\x1b[0m

Chain: ${chain.toUpperCase()} | LLM: ${llmStatus}
`);

// Check for updates, then start
checkForUpdates().finally(() => {
  const monitor = new ContractMonitor(chain, { llm: !noLLM && !!process.env.ANTHROPIC_API_KEY });
  monitor.start().catch(e => {
    console.error('Fatal:', e.message);
    process.exit(1);
  });
});

process.on('SIGINT', () => process.exit(0));
