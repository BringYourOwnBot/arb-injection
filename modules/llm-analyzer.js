// modules/llm-analyzer.js
// Deep analysis of HIGH/CRITICAL contracts using Claude

const AnthropicModule = require('@anthropic-ai/sdk');
require('dotenv').config();

// Handle both ESM and CJS module exports
const Anthropic = AnthropicModule.default || AnthropicModule;
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const SYSTEM_PROMPT = `You are an expert EVM bytecode security auditor specializing in arbitrary call injection vulnerabilities.

Your task is to analyze contracts flagged by static analysis for potential exploitation vectors.

Focus on:
1. ARBITRARY CALL INJECTION - Can an attacker control the target address, calldata, or value of a CALL/DELEGATECALL?
2. ACCESS CONTROL GAPS - Is there truly no access control, or did static analysis miss something?
3. EXPLOITATION PATH - How would an attacker exploit this? What's the attack flow?
4. IMPACT ASSESSMENT - What damage can be done? (drain funds, steal approvals, etc.)

## CRITICAL VERIFICATION STEPS (perform mentally before giving verdict):

### Step 1: GAS CHECK
Would the flagged functions use <30,000 gas for execution?
- YES (<30k) ÔåÆ Likely validation function, NOT arbitrary call
- NO (>50k) ÔåÆ Could be genuine execution with external calls

### Step 2: RETURN CONSISTENCY
Do all inputs (valid/invalid) return the same value?
- All return 0x01/true ÔåÆ Likely format validator
- Different returns ÔåÆ Might execute different paths

### Step 3: INVALID TARGET TEST
Would calling a non-contract address (0xfff...fff) as target succeed?
- YES (returns success) ÔåÆ Validation only (doesn't actually call)
- NO (reverts) ÔåÆ Actual execution attempt

### Step 4: KNOWN ADDRESSES CHECK
Is this a well-known contract? Check the address pattern:
- 0xcA11bde0... ÔåÆ Multicall3 (SAFE - intended functionality)
- 0x1111111... ÔåÆ 1inch Router (SAFE - DEX aggregator)
- 0x3fc91a3... ÔåÆ Uniswap Universal Router (SAFE)
- 0xdef1c0d... ÔåÆ 0x Exchange Proxy (SAFE)

### Step 5: PROXY PATTERN CHECK
Is DELEGATECALL target hardcoded or storage-based?
- Hardcoded implementation address ÔåÆ Proxy pattern, analyze implementation instead
- Storage-based (SLOAD before DELEGATECALL) ÔåÆ EIP-1967 proxy, usually safe

## FALSE POSITIVE PATTERNS:

1. **VIEW/VALIDATION FUNCTIONS** - Accept call-like parameters but only VALIDATE format:
   - Gas estimate <30,000
   - Returns same value regardless of input
   - Calling non-contract addresses still returns success
   - Example: validAddress(address), isValidCall(address[],bytes[])

2. **SELECTOR-RESTRICTED CALLS** - External calls that ALWAYS prepend a fixed selector:
   - Pattern: mstore(ptr, FIXED_SELECTOR) before any call
   - Can only call functions matching that selector, not arbitrary transfer()/approve()
   - Example: 1delta Composer always prepends deltaForwardCompose selector

3. **MULTICALL CONTRACTS** - Legitimate call batching utilities:
   - Multicall3 (0xcA11bde0...) is intentionally permissionless
   - Users can only execute calls they could make directly
   - No special permissions or stored funds to exploit

4. **DEX AGGREGATORS** - Intentionally allow arbitrary calls for routing:
   - 1inch, Paraswap, 0x, Cowswap routers
   - Users only harm themselves with bad parameters
   - Built-in slippage/deadline protections

5. **PROXY CONTRACTS** - DELEGATECALL to implementation:
   - EIP-1167 minimal proxy (363d3d373d3d3d363d73...)
   - Transparent proxy / EIP-1967
   - Analyze the IMPLEMENTATION, not the proxy

If exploitable, provide:
- Severity: CRITICAL / HIGH / MEDIUM
- Attack vector summary (1-2 sentences)
- Exploit calldata example if possible

If FALSE POSITIVE, identify:
- Which pattern applies
- Why it's safe despite static analysis flags`;

async function analyzeContract(contractData) {
  const { address, bytecode, chain, deployer, scanResults, sourceCode } = contractData;

  // Extract pattern detection results
  const knownContract = scanResults.results.knownContract || { isKnown: false };
  const minimalProxy = scanResults.results.minimalProxy || { isMinimalProxy: false };
  const selectorRestricted = scanResults.results.selectorRestricted || { isRestricted: false };
  const viewFunctions = scanResults.results.viewValidationFunctions || [];
  const dexAggregator = scanResults.results.dexAggregator || { isAggregator: false };
  const entryGuard = scanResults.results.entryPointGuard || { hasGuard: false };
  const proxyPattern = scanResults.results.proxyPattern || { isProxy: false };
  const transparentProxy = scanResults.results.transparentProxy || { isTransparentProxy: false };
  const signatureProtection = scanResults.results.signatureProtection || { hasSignatureVerification: false };

  const userPrompt = `Analyze this newly deployed contract for arbitrary call injection:

CONTRACT: ${address}
CHAIN: ${chain}
DEPLOYER: ${deployer}
BYTECODE SIZE: ${(bytecode.length - 2) / 2} bytes

STATIC ANALYSIS RESULTS:
- Verdict: ${scanResults.verdict}
- Access Control: ${scanResults.results.accessControl.type}
- CALLER opcodes: ${scanResults.results.stats.callers}
- SLOAD opcodes: ${scanResults.results.stats.sloads}
- ORIGIN opcodes: ${scanResults.results.stats.origins}
- CALL: ${scanResults.results.stats.calls} | DELEGATECALL: ${scanResults.results.stats.delegatecalls}
- Protected calls: ${scanResults.results.accessControl.protectedCalls}
- Unprotected calls: ${scanResults.results.accessControl.unprotectedCalls}
- CALLDATALOAD: ${scanResults.results.stats.calldataLoads} | CALLDATACOPY: ${scanResults.results.stats.calldataCopies}

PATTERN DETECTION (check for false positives):
- Known contract: ${knownContract.isKnown ? `YES - ${knownContract.name} (${knownContract.type}) - ${knownContract.safe ? 'SAFE' : 'REVIEW'}` : 'NO'}
- Minimal proxy: ${minimalProxy.isMinimalProxy ? `YES - ${minimalProxy.variant} -> ${minimalProxy.implementation}` : 'NO'}
- Proxy pattern: ${proxyPattern.isProxy ? `YES - ${proxyPattern.type} -> ${proxyPattern.implementation}` : 'NO'}
- Transparent proxy: ${transparentProxy.isTransparentProxy ? `YES - admin protected: ${transparentProxy.adminFunctionsProtected ? 'YES' : 'NO'}` : 'NO'}
- Entry-point guard: ${entryGuard.hasGuard ? `YES (${entryGuard.type})` : 'NO'}
- Selector-restricted calls: ${selectorRestricted.isRestricted ? `YES - always uses ${selectorRestricted.selector} (${selectorRestricted.selectorName})` : 'NO'}
- Signature protection: ${signatureProtection.hasSignatureVerification ? `YES (${signatureProtection.confidence} confidence, ecrecover: ${signatureProtection.hasEcrecover}, EIP-712: ${signatureProtection.hasDomainSeparator})` : 'NO'}
- Known view/validation functions: ${viewFunctions.length > 0 ? viewFunctions.map(f => f.name).join(', ') : 'None'}
- DEX aggregator: ${dexAggregator.isAggregator ? `YES (callbacks: ${dexAggregator.callbacks?.join(', ')}, validation: ${dexAggregator.hasFactoryValidation ? 'YES' : 'NO'})` : 'NO'}

RISK INDICATORS:
${scanResults.results.indicators.map(i => `- [${i.risk}] ${i.msg}`).join('\n')}

FUNCTION SELECTORS:
${scanResults.results.selectors.join(', ') || 'None detected'}

BYTECODE (first 2000 chars):
${bytecode.slice(0, 2000)}${bytecode.length > 2000 ? '...' : ''}

${sourceCode ? `VERIFIED SOURCE CODE:
\`\`\`solidity
${sourceCode.slice(0, 15000)}${sourceCode.length > 15000 ? '\n// ... truncated' : ''}
\`\`\`` : 'SOURCE CODE: Not verified on block explorer'}

## Analysis Required:

1. **Check PATTERN DETECTION section first** - If any pattern indicates safe, explain why and mark as FALSE POSITIVE

2. **Perform mental verification steps**:
   - Would gas be <30k? (validation only)
   - Would all inputs return same value? (format validator)
   - Is this a known contract address pattern?
   - Is this a proxy that should be analyzed differently?

3. **If potentially vulnerable**: What's the exploitation path and example calldata?

4. **If FALSE POSITIVE**: Which pattern applies and why?`;

  try {
    const message = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1500,
      temperature: 0.2,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userPrompt }]
    });

    return {
      success: true,
      analysis: message.content[0].text,
      tokens: message.usage
    };
  } catch (error) {
    console.error('LLM Error:', error.message);
    return {
      success: false,
      analysis: `Analysis failed: ${error.message}`,
      tokens: null
    };
  }
}

// Quick check for obvious false positives before sending to LLM
function shouldAnalyze(scanResults) {
  const { results, verdict } = scanResults;

  // PRIORITY 1: Skip known safe contracts entirely
  if (results.knownContract && results.knownContract.isKnown && results.knownContract.safe) {
    return false;
  }

  // PRIORITY 2: Skip minimal proxies - analyze implementation instead
  if (results.minimalProxy && results.minimalProxy.isMinimalProxy) {
    return false;
  }

  // PRIORITY 3: Skip transparent proxies with admin protection
  if (results.transparentProxy && results.transparentProxy.isTransparentProxy && results.transparentProxy.adminFunctionsProtected) {
    return false;
  }

  // PRIORITY 4: Skip signature-protected contracts with HIGH confidence
  if (results.signatureProtection && results.signatureProtection.hasSignatureVerification && results.signatureProtection.confidence === 'HIGH') {
    return false;
  }

  // Only analyze HIGH or CRITICAL
  if (verdict !== 'HIGH' && verdict !== 'CRITICAL') {
    return false;
  }

  // Skip if no CALL opcodes at all
  if (results.stats.calls === 0 && results.stats.delegatecalls === 0) {
    return false;
  }

  // Skip tiny contracts (likely proxies or minimal stubs)
  if (results.stats.calls === 0 && results.stats.delegatecalls === 1) {
    // Likely just a proxy pattern
    return false;
  }

  // Skip if selector-restricted pattern detected
  if (results.selectorRestricted && results.selectorRestricted.isRestricted) {
    return false;
  }

  // Skip if all unprotected calls have hardcoded targets
  if (results.accessControl.unprotectedCalls > 0) {
    const unprotectedWithCalldata = results.indicators.filter(i =>
      i.risk === 'HIGH' && i.msg.includes('user input')
    ).length;

    // If no unprotected calls actually use user input, skip
    if (unprotectedWithCalldata === 0) {
      return false;
    }
  }

  return true;
}

// Enhanced analysis with behavioral verification hints
function getVerificationHints(scanResults) {
  const hints = [];

  // Priority 1: Known address check
  hints.push({
    test: 'KNOWN_ADDRESS_CHECK',
    description: 'Check if contract address is in known-safe list (Multicall3, 1inch, Uniswap, etc.)',
    priority: 'HIGHEST'
  });

  // Priority 2: Execution path trace
  hints.push({
    test: 'EXECUTION_PATH_TRACE',
    description: 'Trace function to verify CALL opcode is actually reachable with test inputs',
    priority: 'HIGH'
  });

  // Suggest gas estimation test
  hints.push({
    test: 'GAS_ESTIMATION',
    description: 'Estimate gas for flagged functions - <30k suggests view/validation only, >50k suggests real execution',
    priority: 'HIGH'
  });

  // Suggest invalid target test
  hints.push({
    test: 'INVALID_TARGET',
    description: 'Test with non-contract address (0xfff...fff) as target - should revert if actually calling',
    priority: 'HIGH'
  });

  // Suggest return consistency test
  hints.push({
    test: 'RETURN_CONSISTENCY',
    description: 'If all inputs (valid token, invalid address, EOA) return same value (e.g., 0x01), likely format validation',
    priority: 'MEDIUM'
  });

  // If DEX aggregator detected, suggest callback test
  if (scanResults.results.dexAggregator && scanResults.results.dexAggregator.isAggregator) {
    hints.push({
      test: 'CALLBACK_VALIDATION',
      description: 'Test callback with fake pool address - check if CREATE2 validation exists',
      priority: 'HIGH'
    });
  }

  // If zero access control, check if calls are actually reachable
  if (scanResults.results.accessControl.type === 'NONE' &&
      scanResults.results.stats.callers === 0 &&
      scanResults.results.stats.sloads === 0) {
    hints.push({
      test: 'REACHABILITY_CHECK',
      description: 'Zero access control detected - verify CALL opcodes are actually reachable with crafted inputs (may be dead code)',
      priority: 'CRITICAL'
    });
  }

  return hints;
}

module.exports = { analyzeContract, shouldAnalyze, getVerificationHints };
