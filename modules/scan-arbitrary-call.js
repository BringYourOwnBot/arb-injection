#!/usr/bin/env node
/**
 * Arbitrary Call Injection Scanner v4
 * - Detects dangerous CALL patterns with user-controlled target/data
 * - Analyzes access control patterns per CALL
 * - Identifies Ownable, AccessControl, whitelist patterns
 * - NEW: Known safe contract detection (Multicall3, 1inch, Uniswap, etc.)
 * - NEW: Minimal proxy (EIP-1167) detection
 * - NEW: Enhanced false positive filtering
 *
 * Usage:
 *   node scan-arbitrary-call.js <bytecode-file>
 *   node scan-arbitrary-call.js <address> --rpc <chain>
 */

const fs = require('fs');
const https = require('https');
const http = require('http');

const OPCODES = {
  STOP: 0x00, ADD: 0x01, MUL: 0x02, SUB: 0x03, DIV: 0x04,
  LT: 0x10, GT: 0x11, SLT: 0x12, SGT: 0x13, EQ: 0x14, ISZERO: 0x15,
  AND: 0x16, OR: 0x17, XOR: 0x18, NOT: 0x19,
  ORIGIN: 0x32, CALLER: 0x33, CALLDATALOAD: 0x35, CALLDATASIZE: 0x36, CALLDATACOPY: 0x37,
  CODECOPY: 0x39, EXTCODESIZE: 0x3b, EXTCODECOPY: 0x3c,
  MLOAD: 0x51, MSTORE: 0x52, MSTORE8: 0x53,
  SLOAD: 0x54, SSTORE: 0x55,
  JUMP: 0x56, JUMPI: 0x57, JUMPDEST: 0x5b,
  PUSH1: 0x60, PUSH32: 0x7f,
  DUP1: 0x80, DUP16: 0x8f,
  SWAP1: 0x90, SWAP16: 0x9f,
  CREATE: 0xf0, CALL: 0xf1, CALLCODE: 0xf2, RETURN: 0xf3,
  DELEGATECALL: 0xf4, CREATE2: 0xf5, STATICCALL: 0xfa,
  REVERT: 0xfd, INVALID: 0xfe, SELFDESTRUCT: 0xff,
};

const OPCODE_NAMES = Object.fromEntries(Object.entries(OPCODES).map(([k, v]) => [v, k]));

// Known function selectors for access control
const ACCESS_CONTROL_SELECTORS = {
  '0x8da5cb5b': 'owner()',
  '0xf2fde38b': 'transferOwnership(address)',
  '0x715018a6': 'renounceOwnership()',
  '0x91d14854': 'hasRole(bytes32,address)',
  '0x2f2ff15d': 'grantRole(bytes32,address)',
  '0xd547741f': 'revokeRole(bytes32,address)',
  '0x36568abe': 'renounceRole(bytes32,address)',
  '0xa217fddf': 'DEFAULT_ADMIN_ROLE()',
  '0x248a9ca3': 'getRoleAdmin(bytes32)',
  '0x9010d07c': 'getRoleMember(bytes32,uint256)',
  '0xca15c873': 'getRoleMemberCount(bytes32)',
};

// DEX swap callback selectors - these are CALLED BY pools, not user-invoked
const DEX_CALLBACK_SELECTORS = {
  '0xfa461e33': 'uniswapV3SwapCallback',
  '0x23a69e75': 'pancakeV3SwapCallback',
  '0x2c8958f6': 'algebraSwapCallback',
  '0x654b6487': 'ramsesV2SwapCallback',
  '0xa1dab4eb': 'solidlyV3SwapCallback',
  '0x3df0212f': 'curveCallback',
  '0x10d1e85c': 'uniswapV2Callback',
};

// Known DEX factory addresses for CREATE2 pool validation
const KNOWN_FACTORIES = {
  'uniswapV3': '1f98431c8ad98523631ae4a59f267346ea31f984',
  'pancakeV3': '0bfbcf9fa4f9c56b0f40a671ad40e0805a091865',
  'algebraV3': '9c2abd632771b433e5e7507bcaa41ca3b25d8544',  // Camelot/Algebra
  'sushiV3': 'bACEB8ec6b9355Dfc0269C18bac9d6E2Bdc29C4F'.toLowerCase(),
};

// Pool init code hashes for validation
const INIT_CODE_HASHES = {
  'uniswapV3': 'e34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54',
  'algebraV3': '6c1bebd370ba84753516bc1393c0d0a6c645856da55f5393ac8ab3d6dbc861d3',
};

// Known selector-restricted patterns (external calls always use this selector)
const SELECTOR_RESTRICTED_PATTERNS = {
  // 1delta: deltaForwardCompose(bytes)
  '6a0c90ff': 'deltaForwardCompose',
  // Add more known patterns here
};

// Known view/validation function selectors that are commonly false positives
const VIEW_VALIDATION_SELECTORS = {
  '0x5c1c8621': 'validAddress(address)',
  '0x8e8f294b': 'isValidSignature(bytes32,bytes)',
  '0x01ffc9a7': 'supportsInterface(bytes4)',
  '0x70a08231': 'balanceOf(address)',
};

// KNOWN SAFE CONTRACTS - These are well-audited, legitimate contracts
// Address (lowercase, no 0x prefix) -> { name, type, safe: true/false }
const KNOWN_SAFE_CONTRACTS = {
  // Multicall3 - Same address on all EVM chains
  'ca11bde05977b3631167028862be2a173976ca11': { name: 'Multicall3', type: 'UTILITY', safe: true },

  // 1inch Router v5 - Same address on most chains
  '1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch v5 Router', type: 'DEX_AGGREGATOR', safe: true },
  '111111125421ca6dc452d289314280a0f8842a65': { name: '1inch v5 AggregationRouter', type: 'DEX_AGGREGATOR', safe: true },

  // Uniswap Universal Router
  '3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': { name: 'Uniswap Universal Router', type: 'DEX_ROUTER', safe: true },
  'ef1c6e67703c7bd7107eed8303fbe6ec2554bf6b': { name: 'Uniswap Universal Router (old)', type: 'DEX_ROUTER', safe: true },

  // Permit2
  '000000000022d473030f116ddee9f6b43ac78ba3': { name: 'Permit2', type: 'UTILITY', safe: true },

  // WETH on various chains
  'c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': { name: 'WETH (Ethereum)', type: 'TOKEN', safe: true },
  '82af49447d8a07e3bd95bd0d56f35241523fbab1': { name: 'WETH (Arbitrum)', type: 'TOKEN', safe: true },
  '4200000000000000000000000000000000000006': { name: 'WETH (Base/OP)', type: 'TOKEN', safe: true },
  'bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c': { name: 'WBNB (BSC)', type: 'TOKEN', safe: true },

  // OpenZeppelin Proxy Admin patterns (by bytecode hash, handled separately)

  // Gnosis Safe / Safe contracts
  'd9db270c1b5e3bd161e8c8503c55ceabee709552': { name: 'Gnosis Safe v1.3.0', type: 'MULTISIG', safe: true },
  '41675c099f32341bf84bfc5382af534df5c7461a': { name: 'Safe Singleton Factory', type: 'FACTORY', safe: true },

  // 0x Protocol
  'def1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', type: 'DEX_AGGREGATOR', safe: true },

  // Cowswap
  '9008d19f58aabd9ed0d60971565aa8510560ab41': { name: 'CoW Protocol Settlement', type: 'DEX_AGGREGATOR', safe: true },

  // Paraswap
  'def171fe48cf0115b1d80b88dc8eab59176fee57': { name: 'Paraswap Augustus', type: 'DEX_AGGREGATOR', safe: true },
};

// Known proxy bytecode patterns (first N bytes that identify proxy type)
const PROXY_BYTECODE_PATTERNS = {
  // EIP-1167 Minimal Proxy: 363d3d373d3d3d363d73...5af43d82803e903d91602b57fd5bf3
  'eip1167': '363d3d373d3d3d363d73',
  // EIP-1167 variant with PUSH0
  'eip1167_push0': '365f5f375f5f365f73',
  // Transparent Proxy pattern (common start)
  'transparent': '60806040526004361061',
};

// OpenZeppelin Transparent Proxy / Admin Proxy function selectors
const TRANSPARENT_PROXY_SELECTORS = {
  '0x3659cfe6': 'upgradeTo(address)',
  '0x4f1ef286': 'upgradeToAndCall(address,bytes)',
  '0x5c60da1b': 'implementation()',
  '0x8f283970': 'changeAdmin(address)',
  '0xf851a440': 'admin()',
};

// EIP-712 Domain separator patterns (common hashes seen in signatures)
const EIP712_PATTERNS = {
  // Common domain separator type hashes
  'domainSeparator': /7f([0-9a-f]{64})/, // PUSH32 with domain hash
  // ECRECOVER precompile address (0x1)
  'ecrecover': '6001', // PUSH1 0x01 (ecrecover precompile)
  // Signature verification pattern: v, r, s params followed by call to 0x1
  'sigVerifyPattern': /35.*36.*37.*6001.*f1|35.*36.*37.*6001.*fa/, // CALLDATALOAD for v,r,s + call to 0x01
};

// Known RPC endpoints
const RPC_ENDPOINTS = {
  'eth': 'https://eth.llamarpc.com', 'ethereum': 'https://eth.llamarpc.com',
  'arb': 'https://arb1.arbitrum.io/rpc', 'arbitrum': 'https://arb1.arbitrum.io/rpc',
  'base': 'https://mainnet.base.org', 'op': 'https://mainnet.optimism.io',
  'polygon': 'https://polygon-rpc.com', 'bsc': 'https://bsc-dataseed.binance.org',
  'avax': 'https://api.avax.network/ext/bc/C/rpc',
  'hyper': 'https://rpc.hyperliquid.xyz/evm', 'hyperliquid': 'https://rpc.hyperliquid.xyz/evm',
};

async function fetchBytecode(address, rpcUrl) {
  return new Promise((resolve, reject) => {
    const url = new URL(rpcUrl);
    const client = url.protocol === 'https:' ? https : http;
    const data = JSON.stringify({ jsonrpc: '2.0', method: 'eth_getCode', params: [address, 'latest'], id: 1 });
    const req = client.request({
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { const json = JSON.parse(body); json.error ? reject(new Error(json.error.message)) : resolve(json.result); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

class BytecodeScanner {
  constructor(bytecode, address = null) {
    this.bytecode = bytecode.replace(/^0x/, '').toLowerCase();
    this.bytes = Buffer.from(this.bytecode, 'hex');
    this.address = address ? address.toLowerCase().replace(/^0x/, '') : null;
    this.opcodes = this.disassemble();
    this.executableEnd = this.findExecutableEnd();
    this.stats = { calls: 0, delegatecalls: 0, staticcalls: 0, calldataLoads: 0, calldataCopies: 0, sloads: 0, callers: 0, origins: 0 };
    this.accessControl = { type: 'NONE', patterns: [], protectedCalls: 0, unprotectedCalls: 0 };

    // NEW: Check if this is a known safe contract FIRST
    this.knownContract = this.checkKnownContract();

    // NEW: Check for minimal proxy pattern EARLY (before other analysis)
    this.minimalProxy = this.detectMinimalProxyPattern();

    this.entryPointGuard = this.detectEntryPointGuard();
    this.hardcodedAddresses = this.extractHardcodedAddresses();
    this.proxyPattern = this.detectProxyPattern();
    this.transparentProxy = this.detectTransparentProxyPattern(); // NEW
    this.signatureProtection = this.detectSignatureProtection(); // NEW
    this.dexAggregator = this.detectDexAggregatorPattern();
    this.selectorRestricted = this.detectSelectorRestrictedPattern();
    this.viewValidationFunctions = this.detectViewValidationFunctions();
  }

  // NEW: Check if contract address is in known safe contracts list
  checkKnownContract() {
    if (!this.address) return null;

    const known = KNOWN_SAFE_CONTRACTS[this.address];
    if (known) {
      return {
        isKnown: true,
        name: known.name,
        type: known.type,
        safe: known.safe
      };
    }
    return { isKnown: false };
  }

  // NEW: Detect EIP-1167 minimal proxy pattern early
  detectMinimalProxyPattern() {
    const result = { isMinimalProxy: false, implementation: null, variant: null };

    // Check for EIP-1167 pattern: 363d3d373d3d3d363d73[20-byte-addr]5af43d82803e903d91602b57fd5bf3
    const eip1167Match = this.bytecode.match(/^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3/);
    if (eip1167Match) {
      result.isMinimalProxy = true;
      result.implementation = '0x' + eip1167Match[1];
      result.variant = 'EIP-1167';
      return result;
    }

    // Check for PUSH0 variant: 365f5f375f5f365f73[20-byte-addr]5af43d5f5f3e5f3d91602a57fd5bf3
    const push0Match = this.bytecode.match(/^365f5f375f5f365f73([0-9a-f]{40})5af4/);
    if (push0Match) {
      result.isMinimalProxy = true;
      result.implementation = '0x' + push0Match[1];
      result.variant = 'EIP-1167-PUSH0';
      return result;
    }

    // Very short contracts with only DELEGATECALL are likely proxies
    if (this.bytes.length < 100) {
      // Check for simple proxy: calldatasize -> delegatecall pattern
      const hasDelegatecall = this.bytecode.includes('f4');
      const hasCalldataSize = this.bytecode.includes('36');
      if (hasDelegatecall && hasCalldataSize) {
        // Extract hardcoded address if present
        const addrMatch = this.bytecode.match(/73([0-9a-f]{40})/);
        if (addrMatch) {
          result.isMinimalProxy = true;
          result.implementation = '0x' + addrMatch[1];
          result.variant = 'Simple-Proxy';
          return result;
        }
      }
    }

    return result;
  }

  // NEW: Detect selector-restricted external call patterns (like 1delta)
  // These contracts prepend a fixed selector before ANY external call,
  // making arbitrary function calls impossible
  detectSelectorRestrictedPattern() {
    const pattern = {
      isRestricted: false,
      selector: null,
      selectorName: null,
      confidence: 'NONE'
    };

    // Look for PUSH4 or PUSH32 containing known restricted selectors before CALL/DELEGATECALL
    for (const [sel, name] of Object.entries(SELECTOR_RESTRICTED_PATTERNS)) {
      // Pattern 1: PUSH4 selector directly
      const push4Pattern = `63${sel}`;
      // Pattern 2: PUSH32 with selector at the start (right-padded)
      const push32Pattern = `7f${sel}`;

      if (this.bytecode.includes(push4Pattern) || this.bytecode.includes(push32Pattern)) {
        // Verify it's near a CALL/DELEGATECALL pattern
        const selIndex = this.bytecode.indexOf(push4Pattern) !== -1 ?
          this.bytecode.indexOf(push4Pattern) :
          this.bytecode.indexOf(push32Pattern);

        // Look ahead for CALL (f1) within reasonable distance
        const ahead = this.bytecode.slice(selIndex, selIndex + 200);
        if (ahead.includes('f1') || ahead.includes('f4')) {
          pattern.isRestricted = true;
          pattern.selector = '0x' + sel;
          pattern.selectorName = name;
          pattern.confidence = 'HIGH';
          return pattern;
        }
      }
    }

    // Heuristic: Look for patterns where MSTORE stores a constant selector before CALL
    // Pattern: 7f[32 bytes with selector]...52...f1 (PUSH32, MSTORE, CALL)
    const mstoreCallPattern = /7f([0-9a-f]{8})[0-9a-f]{56}[0-9a-f]{0,40}52[0-9a-f]{0,100}f1/;
    const match = this.bytecode.match(mstoreCallPattern);
    if (match) {
      const possibleSelector = match[1];
      // Check if this selector is used consistently (appears multiple times)
      const occurrences = (this.bytecode.match(new RegExp(possibleSelector, 'g')) || []).length;
      if (occurrences >= 3) {
        pattern.isRestricted = true;
        pattern.selector = '0x' + possibleSelector;
        pattern.selectorName = 'unknown (detected pattern)';
        pattern.confidence = 'MEDIUM';
      }
    }

    return pattern;
  }

  // NEW: Detect known view/validation functions that are common false positives
  detectViewValidationFunctions() {
    const found = [];
    const selectors = this.extractSelectors();

    for (const [sel, name] of Object.entries(VIEW_VALIDATION_SELECTORS)) {
      if (selectors.includes(sel)) {
        found.push({ selector: sel, name });
      }
    }

    return found;
  }

  // NEW: Detect DEX aggregator patterns with callbacks
  detectDexAggregatorPattern() {
    const pattern = {
      isAggregator: false,
      hasCallbacks: false,
      callbacks: [],
      hasFactoryValidation: false,
      hasInitCodeHash: false,
      hasCreate2Validation: false,
      riskLevel: 'UNKNOWN'
    };

    // Check for callback selectors in bytecode
    const selectors = this.extractSelectors();
    for (const [sel, name] of Object.entries(DEX_CALLBACK_SELECTORS)) {
      if (selectors.includes(sel) || this.bytecode.includes(sel.slice(2))) {
        pattern.hasCallbacks = true;
        pattern.callbacks.push(name);
      }
    }

    if (!pattern.hasCallbacks) return pattern;
    pattern.isAggregator = true;

    // Check for factory address validation (CREATE2 pool verification)
    for (const [name, factory] of Object.entries(KNOWN_FACTORIES)) {
      if (this.bytecode.includes(factory)) {
        pattern.hasFactoryValidation = true;
        break;
      }
    }

    // Check for init code hashes (pool deployment verification)
    for (const [name, hash] of Object.entries(INIT_CODE_HASHES)) {
      if (this.bytecode.includes(hash)) {
        pattern.hasInitCodeHash = true;
        break;
      }
    }

    // Check for CREATE2 pattern (0xff followed by address pattern)
    // The ff opcode in context: ff + factory(20 bytes) + salt + initCodeHash
    const create2Pattern = /ff[0-9a-f]{40}/gi;
    const create2Matches = this.bytecode.match(create2Pattern) || [];
    pattern.hasCreate2Validation = create2Matches.length > 0;

    // Determine risk level based on validation presence
    if (pattern.hasFactoryValidation || pattern.hasInitCodeHash) {
      pattern.riskLevel = 'LOW';  // Properly validates pool addresses
    } else if (pattern.hasCreate2Validation) {
      pattern.riskLevel = 'MEDIUM';  // Has some CREATE2 logic, may validate
    } else {
      // No validation found - callbacks may be exploitable
      pattern.riskLevel = 'HIGH';
    }

    return pattern;
  }

  // NEW: Detect if contract is a pure proxy pattern
  detectProxyPattern() {
    const proxy = { isProxy: false, type: null, implementation: null };

    // Pattern 1: Minimal proxy (EIP-1167 clone)
    // 363d3d373d3d3d363d73[impl]5af43d82803e903d91602b57fd5bf3
    const eip1167Pattern = /363d3d373d3d3d363d73([0-9a-f]{40})5af4/;
    const eip1167Match = this.bytecode.match(eip1167Pattern);
    if (eip1167Match) {
      proxy.isProxy = true;
      proxy.type = 'EIP-1167 Minimal Proxy';
      proxy.implementation = '0x' + eip1167Match[1];
      return proxy;
    }

    // Pattern 2: Fallback-only proxy (fallback does DELEGATECALL to hardcoded address)
    // Look for: CALLDATASIZE -> PUSH0/DUP -> ... -> DELEGATECALL with hardcoded addr before it
    // Common pattern in fallback: 36...73[impl]...f4 (calldatasize ... push20 impl ... delegatecall)
    const fallbackProxyPattern = /365f5f37365f73([0-9a-f]{40})5af4/;
    const fallbackMatch = this.bytecode.match(fallbackProxyPattern);
    if (fallbackMatch) {
      proxy.isProxy = true;
      proxy.type = 'Fallback Proxy';
      proxy.implementation = '0x' + fallbackMatch[1];
      return proxy;
    }

    // Pattern 3: Simple proxy - small contract with DELEGATECALL and hardcoded address
    // If bytecode < 500 bytes and has exactly 1-2 DELEGATECALLs with hardcoded target
    if (this.bytes.length < 500 && this.stats.delegatecalls > 0 && this.stats.delegatecalls <= 2) {
      // Check if DELEGATECALL target is hardcoded
      for (const addr of this.hardcodedAddresses) {
        // If a hardcoded address appears near a DELEGATECALL pattern
        const addrHex = addr.slice(2).toLowerCase();
        const dcPattern = new RegExp(`73${addrHex}.*f4|f4.*73${addrHex}`);
        if (dcPattern.test(this.bytecode)) {
          proxy.isProxy = true;
          proxy.type = 'Simple Proxy';
          proxy.implementation = addr;
          return proxy;
        }
      }
    }

    // Pattern 4: Check for proxy with storage-based implementation (EIP-1967)
    // These load impl from storage slot, harder to detect statically
    // Look for: SLOAD followed by DELEGATECALL within short distance
    const ops = this.executableOps();
    for (let i = 0; i < ops.length - 10; i++) {
      if (ops[i].opcode === OPCODES.SLOAD) {
        const ahead = ops.slice(i, Math.min(i + 15, ops.length));
        if (ahead.some(o => o.opcode === OPCODES.DELEGATECALL)) {
          // Check if this is in a fallback-like context (near start or after selector check)
          if (i < 50 || ops[i].offset < 0x100) {
            proxy.isProxy = true;
            proxy.type = 'EIP-1967 Storage Proxy';
            proxy.implementation = 'dynamic (storage-based)';
            return proxy;
          }
        }
      }
    }

    return proxy;
  }

  // NEW: Detect OpenZeppelin Transparent Proxy pattern by function selectors
  detectTransparentProxyPattern() {
    const result = {
      isTransparentProxy: false,
      hasAdminFunctions: false,
      adminFunctionsProtected: false,
      selectors: []
    };

    const selectors = this.extractSelectors();

    // Check for Transparent Proxy selectors
    let proxySelectors = 0;
    for (const [sel, name] of Object.entries(TRANSPARENT_PROXY_SELECTORS)) {
      if (selectors.includes(sel)) {
        result.selectors.push({ selector: sel, name });
        proxySelectors++;
      }
    }

    // If 3+ proxy selectors found, it's likely a Transparent Proxy
    if (proxySelectors >= 3) {
      result.isTransparentProxy = true;
      result.hasAdminFunctions = true;

      // Check if admin functions are protected (CALLER checks exist)
      const ops = this.executableOps();
      let callerCount = 0;
      for (const op of ops) {
        if (op.opcode === OPCODES.CALLER) callerCount++;
      }

      // Transparent proxies typically have 5-10 CALLER checks for admin verification
      result.adminFunctionsProtected = callerCount >= 3;
    }

    return result;
  }

  // NEW: Detect EIP-712 signature verification pattern
  detectSignatureProtection() {
    const result = {
      hasSignatureVerification: false,
      hasEcrecover: false,
      hasDomainSeparator: false,
      hasExternalVerifier: false,
      confidence: 'NONE'
    };

    // Check for ECRECOVER precompile call pattern
    // Pattern: Prepare data -> call(gas, 0x01, ...) -> check result
    // The address 0x01 is the ECRECOVER precompile

    // Look for PUSH1 0x01 followed by CALL or STATICCALL within reasonable distance
    const ecrecoverPattern = /60015[0-9a-f]{0,40}(f1|fa)/;
    if (ecrecoverPattern.test(this.bytecode)) {
      result.hasEcrecover = true;
      result.hasSignatureVerification = true;
    }

    // Check for PUSH32 with domain separator (common in EIP-712)
    // Domain separators are 32-byte hashes that appear as constants
    const domainSeparatorPattern = /7f([0-9a-f]{64}).*52.*20/; // PUSH32 hash -> MSTORE -> SHA3
    if (domainSeparatorPattern.test(this.bytecode)) {
      result.hasDomainSeparator = true;
    }

    // Check for external signature verification contract call
    // Pattern: STATICCALL to Permit2 (000000000022d473...) or similar
    const permit2Pattern = '000000000022d473030f116ddee9f6b43ac78ba3';
    if (this.bytecode.includes(permit2Pattern)) {
      result.hasExternalVerifier = true;
      result.hasSignatureVerification = true;
    }

    // Check for common signature parameter patterns
    // Signatures have v (1 byte), r (32 bytes), s (32 bytes) = 65 bytes
    // Often loaded via CALLDATALOAD at offsets 0x40, 0x60, 0x80 or similar
    const sigLoadPattern = /35.*35.*35.*20/; // Multiple CALLDATALOADs followed by SHA3
    if (sigLoadPattern.test(this.bytecode) && (result.hasEcrecover || result.hasDomainSeparator)) {
      result.confidence = 'HIGH';
    } else if (result.hasEcrecover && result.hasDomainSeparator) {
      result.confidence = 'HIGH';
    } else if (result.hasExternalVerifier) {
      result.confidence = 'HIGH';
    } else if (result.hasEcrecover || result.hasDomainSeparator) {
      result.confidence = 'MEDIUM';
    }

    return result;
  }

  // NEW: Detect if there's an access control guard at the entry point that gates ALL execution
  detectEntryPointGuard() {
    const guard = { hasGuard: false, type: null, address: null };
    const first150Bytes = this.bytecode.slice(0, 300); // First 150 bytes in hex

    // Pattern 1: Hardcoded owner check at entry
    // 73[40 hex chars = 20 bytes address]331415 = PUSH20 addr, CALLER, EQ
    // or 33...73[addr]...1415 = CALLER ... PUSH20 addr ... EQ
    const ownerPattern = /73([0-9a-f]{40})331415/;
    const ownerMatch = first150Bytes.match(ownerPattern);
    if (ownerMatch) {
      guard.hasGuard = true;
      guard.type = 'hardcoded_owner';
      guard.address = '0x' + ownerMatch[1];
      return guard;
    }

    // Pattern 1b: CALLER then PUSH20 then EQ
    const ownerPattern2 = /3373([0-9a-f]{40})1415/;
    const ownerMatch2 = first150Bytes.match(ownerPattern2);
    if (ownerMatch2) {
      guard.hasGuard = true;
      guard.type = 'hardcoded_owner';
      guard.address = '0x' + ownerMatch2[1];
      return guard;
    }

    // Pattern 2: Whitelist mapping check at entry
    // CALLER(33) -> MSTORE(52) -> ... -> SHA3(20) -> SLOAD(54)
    // Compact pattern: 335f52 or 335f525f6020526... followed by 20...54
    if (first150Bytes.includes('335f52') && first150Bytes.includes('54')) {
      // Check for SHA3 pattern leading to SLOAD
      const sha3SloadPattern = /335f52.*20.*54/;
      if (sha3SloadPattern.test(first150Bytes)) {
        guard.hasGuard = true;
        guard.type = 'whitelist_mapping';
        return guard;
      }
    }

    // Pattern 3: ORIGIN == CALLER check (no contract calls allowed)
    // 32331415 = ORIGIN CALLER EQ
    if (first150Bytes.includes('32331415') || first150Bytes.includes('33321415')) {
      // This alone isn't enough - need to also check for owner
      const hasRevert = first150Bytes.includes('fd'); // REVERT
      if (hasRevert) {
        // Check if there's also an address check nearby
        const addrInEntry = first150Bytes.match(/73([0-9a-f]{40})/);
        if (addrInEntry && !addrInEntry[1].startsWith('ffff')) {
          guard.hasGuard = true;
          guard.type = 'eoa_only_with_owner';
          guard.address = '0x' + addrInEntry[1];
          return guard;
        }
      }
    }

    return guard;
  }

  // NEW: Extract hardcoded addresses from bytecode (PUSH20)
  extractHardcodedAddresses() {
    const addresses = new Set();
    const pattern = /73([0-9a-f]{40})/g;
    let match;
    while ((match = pattern.exec(this.bytecode)) !== null) {
      const addr = match[1];
      // Filter out masks, zero addresses, and obvious bytecode fragments
      if (
        !addr.startsWith('ffff') &&
        !addr.startsWith('0000') &&
        addr !== 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' &&
        // Filter bytecode-like patterns (contain common opcode sequences)
        !addr.includes('5050') &&  // POP POP
        !addr.includes('5f5f') &&  // PUSH0 PUSH0
        !addr.includes('fd5b') &&  // REVERT JUMPDEST
        !addr.includes('5b50') &&  // JUMPDEST POP
        !addr.includes('f3fd') &&  // RETURN REVERT
        !addr.startsWith('d5f8') && // Common metadata pattern
        !addr.startsWith('4146') && // Bytecode fragment
        !addr.startsWith('9190') && // Bytecode fragment
        !addr.includes('565b') &&  // JUMP JUMPDEST
        !addr.includes('6040') &&  // PUSH1 0x40
        // Must have some variety in hex digits (real addresses are more random)
        new Set(addr.split('')).size > 8
      ) {
        addresses.add('0x' + addr);
      }
    }
    return Array.from(addresses);
  }

  // NEW: Check if a CALL/DELEGATECALL has a hardcoded target (PUSH20 before it)
  hasHardcodedTarget(callIndex) {
    const window = this.lookback(callIndex, 15);
    for (let i = window.length - 1; i >= 0; i--) {
      const op = window[i];
      if (op.opcode === 0x73) { // PUSH20
        // Check if this pushed value is a non-mask address
        if (op.value && !op.value.startsWith('ffff') && !op.value.startsWith('0000')) {
          return { hardcoded: true, target: '0x' + op.value };
        }
      }
      // If we hit another CALL or control flow, stop looking
      if ([OPCODES.CALL, OPCODES.DELEGATECALL, OPCODES.STATICCALL, OPCODES.JUMP, OPCODES.JUMPI].includes(op.opcode)) {
        break;
      }
    }
    return { hardcoded: false };
  }

  isPush(op) { return op >= 0x60 && op <= 0x7f; }
  getPushSize(op) { return op - 0x60 + 1; }

  disassemble() {
    const ops = [];
    let i = 0;
    while (i < this.bytes.length) {
      const op = this.bytes[i];
      const entry = { offset: i, opcode: op, name: OPCODE_NAMES[op] || `0x${op.toString(16)}` };
      if (this.isPush(op)) {
        const size = this.getPushSize(op);
        entry.value = this.bytes.slice(i + 1, i + 1 + size).toString('hex');
        i += size;
      }
      ops.push(entry);
      i++;
    }
    return ops;
  }

  findExecutableEnd() {
    for (let i = 0; i < this.opcodes.length; i++) {
      if (this.opcodes[i].opcode === 0xfe) return i;
    }
    return this.opcodes.length;
  }

  executableOps() { return this.opcodes.slice(0, this.executableEnd); }
  lookback(index, count) { return this.opcodes.slice(Math.max(0, index - count), index); }
  lookahead(index, count) { return this.opcodes.slice(index + 1, Math.min(this.executableEnd, index + 1 + count)); }

  // Detect access control patterns
  detectAccessControl() {
    const selectors = this.extractSelectors();
    const patterns = [];

    // Check for Ownable pattern
    const hasOwner = selectors.includes('0x8da5cb5b');
    const hasTransferOwnership = selectors.includes('0xf2fde38b');
    if (hasOwner || hasTransferOwnership) {
      patterns.push('Ownable');
    }

    // Check for AccessControl pattern
    const hasHasRole = selectors.includes('0x91d14854');
    const hasGrantRole = selectors.includes('0x2f2ff15d');
    if (hasHasRole || hasGrantRole) {
      patterns.push('AccessControl');
    }

    // Check for CALLER opcode usage (msg.sender checks)
    const callerCount = this.executableOps().filter(o => o.opcode === OPCODES.CALLER).length;
    this.stats.callers = callerCount;

    // Detect onlyOwner pattern: CALLER -> SLOAD -> EQ -> ISZERO -> JUMPI -> REVERT
    // Look for sequences where CALLER is followed by SLOAD within 10 ops, then EQ
    let onlyOwnerPatterns = 0;
    const ops = this.executableOps();
    for (let i = 0; i < ops.length - 5; i++) {
      if (ops[i].opcode === OPCODES.CALLER) {
        // Look ahead for SLOAD + EQ pattern
        const ahead = ops.slice(i, Math.min(i + 15, ops.length));
        const aheadOps = ahead.map(o => o.opcode);
        if (aheadOps.includes(OPCODES.SLOAD) && aheadOps.includes(OPCODES.EQ)) {
          onlyOwnerPatterns++;
        }
      }
    }

    if (onlyOwnerPatterns > 0) {
      patterns.push(`onlyOwner modifier (${onlyOwnerPatterns}x)`);
    }

    // Detect whitelist/mapping pattern: CALLER -> hash computation -> SLOAD
    let whitelistPatterns = 0;
    for (let i = 0; i < ops.length - 10; i++) {
      if (ops[i].opcode === OPCODES.CALLER) {
        const ahead = ops.slice(i, Math.min(i + 20, ops.length));
        const aheadOps = ahead.map(o => o.opcode);
        // Look for: CALLER -> ... -> MSTORE -> PUSH -> MSTORE -> PUSH -> PUSH -> SHA3 -> SLOAD
        // Simplified: CALLER followed by multiple MSTORE then SLOAD
        const mstoreCount = aheadOps.filter(o => o === OPCODES.MSTORE).length;
        if (mstoreCount >= 2 && aheadOps.includes(OPCODES.SLOAD)) {
          whitelistPatterns++;
        }
      }
    }

    if (whitelistPatterns > 0) {
      patterns.push(`Whitelist/mapping check (${whitelistPatterns}x)`);
    }

    // Check for ORIGIN-based access control (tx.origin check)
    const originCount = this.executableOps().filter(o => o.opcode === OPCODES.ORIGIN).length;
    this.stats.origins = originCount;

    // Detect ORIGIN + EQ pattern (hardcoded tx.origin check)
    let originPatterns = 0;
    for (let i = 0; i < ops.length - 3; i++) {
      if (ops[i].opcode === OPCODES.ORIGIN) {
        const ahead = ops.slice(i, Math.min(i + 5, ops.length));
        const aheadOps = ahead.map(o => o.opcode);
        if (aheadOps.includes(OPCODES.EQ)) {
          originPatterns++;
        }
      }
    }

    if (originPatterns > 0) {
      patterns.push(`tx.origin check (${originPatterns}x)`);
    }

    // Determine overall access control type
    if (patterns.includes('AccessControl')) {
      this.accessControl.type = 'AccessControl (RBAC)';
    } else if (patterns.includes('Ownable')) {
      this.accessControl.type = 'Ownable';
    } else if (whitelistPatterns > 0 || onlyOwnerPatterns > 0) {
      this.accessControl.type = 'Custom';
    } else if (originPatterns > 0) {
      this.accessControl.type = 'tx.origin restricted';
    } else if (callerCount > 0) {
      this.accessControl.type = 'Basic (CALLER checks)';
    }

    this.accessControl.patterns = patterns;
    return this.accessControl;
  }

  // Analyze a specific CALL for access control
  analyzeCallProtection(callIndex, opcode = OPCODES.CALL) {
    const windowSize = 100;
    const window = this.lookback(callIndex, windowSize);
    const windowOps = window.map(o => o.opcode);

    const analysis = {
      hasCallerCheck: false,
      hasSloadBeforeCall: false,
      hasJumpiBeforeCall: false,
      hasRevertPath: false,
      usesCalldata: false,
      usesMload: false,
      hasHardcodedTarget: false,
      hardcodedTarget: null,
      protectionLevel: 'NONE'
    };

    // NEW: Check if entry-point guard protects this call
    if (this.entryPointGuard.hasGuard) {
      analysis.hasCallerCheck = true;
      analysis.protectionLevel = 'HIGH';
      analysis.entryGuarded = true;
    }

    // NEW: Check if CALL/DELEGATECALL has hardcoded target
    const targetCheck = this.hasHardcodedTarget(callIndex);
    if (targetCheck.hardcoded) {
      analysis.hasHardcodedTarget = true;
      analysis.hardcodedTarget = targetCheck.target;
      // Hardcoded target is much safer - upgrade protection
      if (analysis.protectionLevel === 'NONE') {
        analysis.protectionLevel = 'MEDIUM';
      }
    }

    // Check for CALLER in window
    analysis.hasCallerCheck = analysis.hasCallerCheck || windowOps.includes(OPCODES.CALLER);

    // Check for SLOAD (storage read - could be owner/role check)
    analysis.hasSloadBeforeCall = windowOps.includes(OPCODES.SLOAD);

    // Check for JUMPI (conditional - access control branch)
    analysis.hasJumpiBeforeCall = windowOps.includes(OPCODES.JUMPI);

    // Check for user input flow
    analysis.usesCalldata = windowOps.includes(OPCODES.CALLDATALOAD) || windowOps.includes(OPCODES.CALLDATACOPY);
    analysis.usesMload = windowOps.includes(OPCODES.MLOAD);

    // Determine protection level (if not already set by entry guard)
    if (!analysis.entryGuarded) {
      if (analysis.hasCallerCheck && analysis.hasSloadBeforeCall && analysis.hasJumpiBeforeCall) {
        analysis.protectionLevel = 'HIGH';  // Likely has modifier
      } else if (analysis.hasSloadBeforeCall && analysis.hasJumpiBeforeCall) {
        analysis.protectionLevel = 'MEDIUM';  // Has storage check
      } else if (analysis.hasHardcodedTarget) {
        analysis.protectionLevel = 'MEDIUM';  // Hardcoded target (proxy pattern)
      } else if (analysis.hasCallerCheck) {
        analysis.protectionLevel = 'LOW';  // Only caller check, might be logging
      }
    }

    return analysis;
  }

  scan(silent = false) {
    const log = silent ? () => {} : console.log.bind(console);

    log('\n\x1b[1m=== ARBITRARY CALL INJECTION SCANNER v4 ===\x1b[0m\n');
    log(`Bytecode: ${this.bytes.length} bytes | Executable: ${this.executableEnd} instructions\n`);

    // NEW: Check for known safe contracts FIRST
    if (this.knownContract && this.knownContract.isKnown) {
      log(`\x1b[32m--- KNOWN CONTRACT DETECTED ---\x1b[0m`);
      log(`Name: ${this.knownContract.name}`);
      log(`Type: ${this.knownContract.type}`);
      log(`Status: ${this.knownContract.safe ? '\x1b[32mSAFE (whitelisted)\x1b[0m' : '\x1b[33mKNOWN (review required)\x1b[0m'}\n`);
    }

    // NEW: Check for minimal proxy pattern EARLY
    if (this.minimalProxy && this.minimalProxy.isMinimalProxy) {
      log(`\x1b[32m--- MINIMAL PROXY DETECTED ---\x1b[0m`);
      log(`Variant: ${this.minimalProxy.variant}`);
      log(`Implementation: ${this.minimalProxy.implementation}`);
      log(`\x1b[32mThis is a standard proxy pattern - analyze the implementation instead.\x1b[0m\n`);
    }

    // Count opcodes
    for (const op of this.executableOps()) {
      if (op.opcode === OPCODES.CALL) this.stats.calls++;
      else if (op.opcode === OPCODES.DELEGATECALL) this.stats.delegatecalls++;
      else if (op.opcode === OPCODES.STATICCALL) this.stats.staticcalls++;
      else if (op.opcode === OPCODES.CALLDATALOAD) this.stats.calldataLoads++;
      else if (op.opcode === OPCODES.CALLDATACOPY) this.stats.calldataCopies++;
      else if (op.opcode === OPCODES.SLOAD) this.stats.sloads++;
      else if (op.opcode === OPCODES.ORIGIN) this.stats.origins++;
    }

    // Detect access control
    this.detectAccessControl();

    log('\x1b[36m--- OPCODE STATISTICS ---\x1b[0m');
    log(`CALL: ${this.stats.calls} | DELEGATECALL: ${this.stats.delegatecalls} | STATICCALL: ${this.stats.staticcalls}`);
    log(`CALLDATALOAD: ${this.stats.calldataLoads} | CALLDATACOPY: ${this.stats.calldataCopies}`);
    log(`SLOAD: ${this.stats.sloads} | CALLER: ${this.stats.callers} | ORIGIN: ${this.stats.origins}`);

    // Access Control Summary
    log('\n\x1b[36m--- ACCESS CONTROL ---\x1b[0m');
    log(`Type: ${this.accessControl.type || 'None detected'}`);
    if (this.accessControl.patterns.length > 0) {
      log(`Patterns: ${this.accessControl.patterns.join(', ')}`);
    }

    // NEW: Entry-point guard detection
    if (this.entryPointGuard.hasGuard) {
      log(`\x1b[32mEntry Guard: ${this.entryPointGuard.type}${this.entryPointGuard.address ? ' (' + this.entryPointGuard.address.slice(0, 12) + '...)' : ''}\x1b[0m`);
      this.accessControl.type = this.accessControl.type === 'NONE' ? 'Entry-guarded' : this.accessControl.type + ' + Entry-guarded';
    }

    // NEW: Hardcoded addresses
    if (this.hardcodedAddresses.length > 0 && this.hardcodedAddresses.length <= 10) {
      log(`Hardcoded addresses: ${this.hardcodedAddresses.length} found`);
    }

    // NEW: Proxy pattern detection
    if (this.proxyPattern.isProxy) {
      log(`\x1b[33mProxy Detected: ${this.proxyPattern.type}\x1b[0m`);
      log(`Implementation: ${this.proxyPattern.implementation}`);
    }

    // NEW: Transparent Proxy detection
    if (this.transparentProxy && this.transparentProxy.isTransparentProxy) {
      log(`\n\x1b[32m--- TRANSPARENT PROXY DETECTED ---\x1b[0m`);
      log(`Admin functions: ${this.transparentProxy.selectors.map(s => s.name).join(', ')}`);
      log(`Admin protection: ${this.transparentProxy.adminFunctionsProtected ? '\x1b[32mYES\x1b[0m' : '\x1b[31mNO\x1b[0m'}`);
      log(`\x1b[32mThis is an OpenZeppelin-style upgradeable proxy - DELEGATECALLs are intended\x1b[0m`);
    }

    // NEW: Signature protection detection
    if (this.signatureProtection && this.signatureProtection.hasSignatureVerification) {
      log(`\n\x1b[32m--- SIGNATURE PROTECTION DETECTED ---\x1b[0m`);
      log(`ECRECOVER: ${this.signatureProtection.hasEcrecover ? 'YES' : 'NO'}`);
      log(`EIP-712 Domain: ${this.signatureProtection.hasDomainSeparator ? 'YES' : 'NO'}`);
      log(`External Verifier: ${this.signatureProtection.hasExternalVerifier ? 'YES' : 'NO'}`);
      log(`Confidence: ${this.signatureProtection.confidence}`);
      this.accessControl.hasSignatureVerification = true;
    }

    // NEW: DEX aggregator pattern detection
    if (this.dexAggregator.isAggregator) {
      log(`\n\x1b[36m--- DEX AGGREGATOR DETECTED ---\x1b[0m`);
      log(`Callbacks: ${this.dexAggregator.callbacks.join(', ')}`);
      log(`Factory validation: ${this.dexAggregator.hasFactoryValidation ? '\x1b[32mYES\x1b[0m' : '\x1b[31mNO\x1b[0m'}`);
      log(`Init code hash: ${this.dexAggregator.hasInitCodeHash ? '\x1b[32mYES\x1b[0m' : '\x1b[31mNO\x1b[0m'}`);
      log(`CREATE2 patterns: ${this.dexAggregator.hasCreate2Validation ? '\x1b[33mFOUND\x1b[0m' : '\x1b[31mNONE\x1b[0m'}`);
      const riskColor = { LOW: '\x1b[32m', MEDIUM: '\x1b[33m', HIGH: '\x1b[31m' }[this.dexAggregator.riskLevel];
      log(`Callback risk: ${riskColor}${this.dexAggregator.riskLevel}\x1b[0m`);
    }

    // NEW: Selector-restricted pattern detection (e.g., 1delta)
    if (this.selectorRestricted.isRestricted) {
      log(`\n\x1b[32m--- SELECTOR-RESTRICTED CALLS DETECTED ---\x1b[0m`);
      log(`External calls always use selector: ${this.selectorRestricted.selector} (${this.selectorRestricted.selectorName})`);
      log(`Confidence: ${this.selectorRestricted.confidence}`);
      log(`\x1b[32mThis pattern prevents arbitrary function calls (e.g., transfer/approve)\x1b[0m`);
    }

    // NEW: Known view/validation functions
    if (this.viewValidationFunctions.length > 0) {
      log(`\n\x1b[33m--- VIEW/VALIDATION FUNCTIONS ---\x1b[0m`);
      for (const fn of this.viewValidationFunctions) {
        log(`  ${fn.selector}: ${fn.name} (likely false positive)`);
      }
    }

    // Analyze each CALL
    const indicators = [];
    const callAnalysis = [];
    const callOps = this.executableOps().map((o, i) => ({ ...o, index: i })).filter(o => o.opcode === OPCODES.CALL);

    log('\n\x1b[36m--- CALL ANALYSIS ---\x1b[0m');

    for (const call of callOps) {
      const protection = this.analyzeCallProtection(call.index);
      callAnalysis.push({ offset: call.offset, ...protection });

      const protColor = { HIGH: '\x1b[32m', MEDIUM: '\x1b[33m', LOW: '\x1b[33m', NONE: '\x1b[31m' }[protection.protectionLevel];
      const inputFlag = protection.usesCalldata ? ' [CALLDATA]' : '';

      log(`  CALL@0x${call.offset.toString(16).padStart(4, '0')}: ${protColor}${protection.protectionLevel}\x1b[0m protection${inputFlag}`);

      if (protection.protectionLevel === 'NONE' && protection.usesCalldata) {
        this.accessControl.unprotectedCalls++;
        indicators.push({
          risk: 'HIGH',
          msg: `CALL@0x${call.offset.toString(16)}: Unprotected with user input - potential arbitrary call`,
          offset: call.offset
        });
      } else if (protection.protectionLevel === 'NONE') {
        this.accessControl.unprotectedCalls++;
        indicators.push({
          risk: 'MEDIUM',
          msg: `CALL@0x${call.offset.toString(16)}: No visible access control`,
          offset: call.offset
        });
      } else {
        this.accessControl.protectedCalls++;
      }
    }

    // DELEGATECALL analysis - now checks for hardcoded targets
    let allDelegateCallsHaveHardcodedTarget = true;
    if (this.stats.delegatecalls > 0) {
      const dcOps = this.executableOps().map((o, i) => ({ ...o, index: i })).filter(o => o.opcode === OPCODES.DELEGATECALL);
      for (const dc of dcOps) {
        const protection = this.analyzeCallProtection(dc.index, OPCODES.DELEGATECALL);

        // NEW: Check if target is in hardcoded addresses list (broader check)
        const hasHardcodedInBytecode = this.hardcodedAddresses.length > 0 && this.hardcodedAddresses.length <= 5;

        // NEW: If DELEGATECALL has hardcoded target, it's a proxy pattern - much safer
        if (protection.hasHardcodedTarget) {
          log(`  DELEGATECALL@0x${dc.offset.toString(16)}: \x1b[32mPROXY\x1b[0m -> ${protection.hardcodedTarget.slice(0, 12)}...`);
          indicators.push({
            risk: 'LOW',
            msg: `DELEGATECALL@0x${dc.offset.toString(16)}: Proxy pattern with hardcoded impl ${protection.hardcodedTarget.slice(0, 12)}...`,
            offset: dc.offset
          });
        } else if (hasHardcodedInBytecode && this.bytes.length < 20000) {
          // Contract has few hardcoded addresses and is reasonably sized - likely uses those for DELEGATECALL
          allDelegateCallsHaveHardcodedTarget = true; // Assume proxy-like
          log(`  DELEGATECALL@0x${dc.offset.toString(16)}: \x1b[33mLIKELY PROXY\x1b[0m (hardcoded impls in bytecode)`);
          indicators.push({
            risk: 'MEDIUM',
            msg: `DELEGATECALL@0x${dc.offset.toString(16)}: Likely proxy (${this.hardcodedAddresses.length} hardcoded addrs in contract)`,
            offset: dc.offset
          });
        } else if (protection.protectionLevel === 'NONE' && !this.entryPointGuard.hasGuard) {
          allDelegateCallsHaveHardcodedTarget = false;
          indicators.push({ risk: 'CRITICAL', msg: `DELEGATECALL@0x${dc.offset.toString(16)}: Unprotected!`, offset: dc.offset });
        } else if (protection.protectionLevel === 'NONE' && this.entryPointGuard.hasGuard) {
          // Entry guard protects it
          indicators.push({ risk: 'MEDIUM', msg: `DELEGATECALL@0x${dc.offset.toString(16)}: Entry-guarded`, offset: dc.offset });
        } else {
          indicators.push({ risk: 'MEDIUM', msg: `DELEGATECALL@0x${dc.offset.toString(16)}: Protected (${protection.protectionLevel})`, offset: dc.offset });
        }
      }
    }
    this.allDelegateCallsHaveHardcodedTarget = allDelegateCallsHaveHardcodedTarget;

    // Aggregator pattern detection
    const selectors = this.extractSelectors();
    const knownAggregators = ['0x12aa3caf', '0x2e95b6c8', '0xe449022e', '0x0502b1c5', '0x78e3214f', '0x8af033fb'];
    if (selectors.some(s => knownAggregators.includes(s.toLowerCase()))) {
      indicators.push({ risk: 'HIGH', msg: 'Known DEX aggregator selector - likely has arbitrary call by design' });
    }

    // NEW: DEX aggregator callback risk assessment
    if (this.dexAggregator.isAggregator) {
      if (this.dexAggregator.riskLevel === 'HIGH') {
        indicators.push({
          risk: 'HIGH',
          msg: `DEX aggregator with ${this.dexAggregator.callbacks.length} callbacks - NO pool validation found (potential callback exploitation)`
        });
      } else if (this.dexAggregator.riskLevel === 'MEDIUM') {
        indicators.push({
          risk: 'MEDIUM',
          msg: `DEX aggregator with callbacks - has CREATE2 patterns but no known factory addresses`
        });
      } else {
        indicators.push({
          risk: 'LOW',
          msg: `DEX aggregator with validated callbacks (factory/initCodeHash present)`
        });
      }
    }

    // Heavy calldata heuristic
    if (this.stats.calldataLoads > 15 && this.stats.calls > 3 && this.accessControl.unprotectedCalls > 0) {
      indicators.push({ risk: 'HIGH', msg: `Heavy calldata (${this.stats.calldataLoads}) + ${this.accessControl.unprotectedCalls} unprotected calls` });
    }

    // NEW: Selector-restricted pattern indicator (reduces risk)
    if (this.selectorRestricted.isRestricted) {
      indicators.push({
        risk: 'LOW',
        msg: `Selector-restricted calls: always uses ${this.selectorRestricted.selector} (${this.selectorRestricted.selectorName}) - arbitrary calls NOT possible`
      });
    }

    // NEW: View/validation function warning
    if (this.viewValidationFunctions.length > 0) {
      indicators.push({
        risk: 'LOW',
        msg: `Contract has ${this.viewValidationFunctions.length} known view/validation function(s) - verify flagged selectors are not false positives`
      });
    }

    // NEW: Transparent Proxy pattern indicator
    if (this.transparentProxy && this.transparentProxy.isTransparentProxy) {
      if (this.transparentProxy.adminFunctionsProtected) {
        indicators.push({
          risk: 'LOW',
          msg: `OpenZeppelin Transparent Proxy with admin-protected upgrade functions`
        });
      } else {
        indicators.push({
          risk: 'MEDIUM',
          msg: `Transparent Proxy pattern detected - verify admin functions are protected`
        });
      }
    }

    // NEW: Signature protection indicator
    if (this.signatureProtection && this.signatureProtection.hasSignatureVerification) {
      const conf = this.signatureProtection.confidence;
      if (conf === 'HIGH') {
        indicators.push({
          risk: 'LOW',
          msg: `EIP-712/ECRECOVER signature verification detected - execution requires valid signatures`
        });
      } else if (conf === 'MEDIUM') {
        indicators.push({
          risk: 'MEDIUM',
          msg: `Possible signature verification detected - verify access control pattern`
        });
      }
    }

    log(`\n  Summary: ${this.accessControl.protectedCalls} protected, ${this.accessControl.unprotectedCalls} unprotected`);

    return {
      stats: this.stats,
      indicators,
      selectors,
      accessControl: this.accessControl,
      callAnalysis,
      // Pattern detection results for LLM analysis
      knownContract: this.knownContract,
      minimalProxy: this.minimalProxy,
      selectorRestricted: this.selectorRestricted,
      viewValidationFunctions: this.viewValidationFunctions,
      dexAggregator: this.dexAggregator,
      proxyPattern: this.proxyPattern,
      entryPointGuard: this.entryPointGuard,
      // NEW: Additional false positive pattern detections
      transparentProxy: this.transparentProxy,
      signatureProtection: this.signatureProtection
    };
  }

  extractSelectors() {
    const selectors = new Set();
    const pattern = /63([0-9a-f]{8})(?:14|81)/g;
    let match;
    while ((match = pattern.exec(this.bytecode)) !== null) {
      selectors.add('0x' + match[1]);
    }
    return Array.from(selectors);
  }

  printReport(results) {
    console.log('\n\x1b[36m--- FUNCTION SELECTORS ---\x1b[0m');
    const acSelectors = results.selectors.filter(s => ACCESS_CONTROL_SELECTORS[s]);
    const otherSelectors = results.selectors.filter(s => !ACCESS_CONTROL_SELECTORS[s]);

    if (acSelectors.length > 0) {
      console.log('Access Control: ' + acSelectors.map(s => `${s} (${ACCESS_CONTROL_SELECTORS[s]})`).join(', '));
    }
    if (otherSelectors.length > 0) {
      console.log('Other: ' + otherSelectors.slice(0, 10).join(', ') + (otherSelectors.length > 10 ? ` ... +${otherSelectors.length - 10}` : ''));
    }

    console.log('\n\x1b[36m--- RISK INDICATORS ---\x1b[0m\n');

    if (results.indicators.length === 0) {
      console.log('No suspicious patterns detected.\n');
    } else {
      const sorted = results.indicators.sort((a, b) => ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[a.risk] - { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[b.risk]));
      for (const ind of sorted) {
        const color = { CRITICAL: '\x1b[31m', HIGH: '\x1b[33m', MEDIUM: '\x1b[36m', LOW: '\x1b[32m' }[ind.risk] || '';
        console.log(`${color}[${ind.risk}]\x1b[0m ${ind.msg}`);
      }
      console.log('');
    }

    const hasCritical = results.indicators.some(i => i.risk === 'CRITICAL');
    const highCount = results.indicators.filter(i => i.risk === 'HIGH').length;
    const hasCalldataCall = results.indicators.some(i => i.msg.includes('user input') || i.msg.includes('CALLDATA'));
    const zeroAccessControl = results.accessControl.type === 'NONE' && this.stats.callers === 0 && this.stats.sloads === 0 && this.stats.origins === 0;

    console.log('\x1b[1m--- VERDICT ---\x1b[0m\n');

    // PRIORITY 1: Known safe contracts
    if (this.knownContract && this.knownContract.isKnown && this.knownContract.safe) {
      console.log('\x1b[32m[KNOWN_SAFE] Whitelisted Contract\x1b[0m');
      console.log(`Name: ${this.knownContract.name}`);
      console.log(`Type: ${this.knownContract.type}`);
      console.log('This is a well-known, audited contract. No further analysis needed.\n');
      return 'KNOWN_SAFE';
    }

    // PRIORITY 2: Minimal proxy pattern
    if (this.minimalProxy && this.minimalProxy.isMinimalProxy) {
      console.log('\x1b[32m[MINIMAL_PROXY] EIP-1167 Clone Detected\x1b[0m');
      console.log(`Variant: ${this.minimalProxy.variant}`);
      console.log(`Implementation: ${this.minimalProxy.implementation}`);
      console.log('This is a minimal proxy - analyze the IMPLEMENTATION contract instead.\n');
      return 'MINIMAL_PROXY';
    }

    // NEW: Check for selector-restricted pattern first (prevents arbitrary calls)
    if (this.selectorRestricted && this.selectorRestricted.isRestricted) {
      const conf = this.selectorRestricted.confidence;
      if (conf === 'HIGH') {
        console.log('\x1b[32m[LOW] SELECTOR-RESTRICTED EXTERNAL CALLS\x1b[0m');
        console.log(`All external calls use fixed selector ${this.selectorRestricted.selector} (${this.selectorRestricted.selectorName})`);
        console.log('Arbitrary function calls (transfer/approve) are NOT possible.\n');
        return 'LOW';
      } else {
        console.log('\x1b[33m[MEDIUM] LIKELY SELECTOR-RESTRICTED CALLS\x1b[0m');
        console.log(`External calls appear to use fixed selector ${this.selectorRestricted.selector}`);
        console.log('Needs manual verification to confirm.\n');
        return 'MEDIUM';
      }
    }

    // NEW: Check for proxy pattern
    if (this.proxyPattern && this.proxyPattern.isProxy) {
      if (this.proxyPattern.implementation && this.proxyPattern.implementation !== 'dynamic (storage-based)') {
        console.log('\x1b[33m[PROXY] Pure proxy contract detected\x1b[0m');
        console.log(`Type: ${this.proxyPattern.type}`);
        console.log(`Implementation: ${this.proxyPattern.implementation}\n`);
        return 'PROXY';
      }
    }

    // NEW: Check for Transparent Proxy (OpenZeppelin style)
    if (this.transparentProxy && this.transparentProxy.isTransparentProxy && this.transparentProxy.adminFunctionsProtected) {
      console.log('\x1b[32m[PROXY] Transparent Upgradeable Proxy detected\x1b[0m');
      console.log(`Admin functions: ${this.transparentProxy.selectors.map(s => s.name).join(', ')}`);
      console.log('DELEGATECALLs are admin-only upgrade functions, not arbitrary call injection.\n');
      return 'PROXY';
    }

    // NEW: Check for signature-protected contracts
    if (this.signatureProtection && this.signatureProtection.hasSignatureVerification && this.signatureProtection.confidence === 'HIGH') {
      console.log('\x1b[32m[LOW] SIGNATURE-PROTECTED EXECUTION\x1b[0m');
      console.log('Contract uses EIP-712/ECRECOVER for access control');
      console.log('Execution requires valid signatures from authorized signers.\n');
      return 'LOW';
    }

    // NEW: If DELEGATECALLs exist but all appear to use hardcoded targets, downgrade
    if (hasCritical && this.allDelegateCallsHaveHardcodedTarget && this.hardcodedAddresses.length > 0) {
      console.log('\x1b[33m[MEDIUM] DELEGATECALL with likely hardcoded targets\x1b[0m');
      console.log(`Contract has ${this.hardcodedAddresses.length} hardcoded addresses - likely proxy pattern\n`);
      return 'MEDIUM';
    } else if (hasCritical) {
      console.log('\x1b[31m[CRITICAL] ARBITRARY CALL INJECTION CONFIRMED\x1b[0m');
      console.log('Unprotected DELEGATECALL or critical pattern detected\n');
      return 'CRITICAL';
    } else if (zeroAccessControl && hasCalldataCall && results.accessControl.unprotectedCalls > 0) {
      // No CALLER, no SLOAD, unprotected CALL with user input = definite arbitrary call
      console.log('\x1b[31m[CRITICAL] ARBITRARY CALL INJECTION - NO ACCESS CONTROL\x1b[0m');
      console.log('Contract has ZERO access control (no CALLER/SLOAD) with user-controlled CALL\n');
      return 'CRITICAL';
    } else if (highCount >= 2) {
      console.log('\x1b[31m[HIGH] ARBITRARY CALL INJECTION PROBABLE\x1b[0m');
      console.log(`${highCount} high-risk indicators found\n`);
      return 'HIGH';
    } else if (highCount === 1 && hasCalldataCall) {
      console.log('\x1b[31m[HIGH] ARBITRARY CALL INJECTION LIKELY\x1b[0m');
      console.log('Unprotected CALL with user-controlled input detected\n');
      return 'HIGH';
    } else if (highCount === 1) {
      console.log('\x1b[33m[MEDIUM-HIGH] Potential arbitrary call injection\x1b[0m');
      console.log('Review unprotected CALL targets\n');
      return 'MEDIUM-HIGH';
    } else if (results.accessControl.unprotectedCalls > 0) {
      console.log('\x1b[36m[MEDIUM] Some unprotected calls detected\x1b[0m');
      console.log('May be intentional (e.g., token transfers)\n');
      return 'MEDIUM';
    } else {
      console.log('\x1b[32m[LOW] No obvious arbitrary call patterns\x1b[0m');
      console.log('All CALLs appear protected\n');
      return 'LOW';
    }
  }

  // Silent verdict computation for programmatic use
  getVerdict(results) {
    // PRIORITY 1: Known safe contracts - return immediately
    if (this.knownContract && this.knownContract.isKnown && this.knownContract.safe) {
      return 'KNOWN_SAFE';
    }

    // PRIORITY 2: Minimal proxy pattern - analyze implementation instead
    if (this.minimalProxy && this.minimalProxy.isMinimalProxy) {
      return 'MINIMAL_PROXY';
    }

    // PRIORITY 3: Transparent Proxy with admin protection
    if (this.transparentProxy && this.transparentProxy.isTransparentProxy && this.transparentProxy.adminFunctionsProtected) {
      return 'PROXY';
    }

    const hasCritical = results.indicators.some(i => i.risk === 'CRITICAL');
    const highCount = results.indicators.filter(i => i.risk === 'HIGH').length;
    const hasCalldataCall = results.indicators.some(i => i.msg.includes('user input') || i.msg.includes('CALLDATA'));
    const zeroAccessControl = results.accessControl.type === 'NONE' && this.stats.callers === 0 && this.stats.sloads === 0 && this.stats.origins === 0;

    // NEW: Signature protection significantly reduces risk
    const hasSignatureProtection = this.signatureProtection &&
      this.signatureProtection.hasSignatureVerification &&
      this.signatureProtection.confidence === 'HIGH';

    // NEW: Entry-point guard significantly reduces risk
    const hasEntryGuard = this.entryPointGuard && this.entryPointGuard.hasGuard;

    // NEW: Selector-restricted pattern makes arbitrary calls impossible
    const hasSelectorRestriction = this.selectorRestricted && this.selectorRestricted.isRestricted;
    if (hasSelectorRestriction) {
      // External calls are limited to specific selectors - not exploitable for arbitrary calls
      return this.selectorRestricted.confidence === 'HIGH' ? 'LOW' : 'MEDIUM';
    }

    // NEW: Signature-protected contracts - execution requires valid signatures
    if (hasSignatureProtection) {
      // Even if flagged as HIGH/CRITICAL, signature verification blocks unauthorized calls
      if (hasCritical) return 'MEDIUM';
      if (highCount >= 2) return 'MEDIUM';
      return 'LOW';
    }

    // NEW: If contract only has known view/validation selectors among flagged functions, downgrade
    const hasOnlyViewFunctions = this.viewValidationFunctions &&
      this.viewValidationFunctions.length > 0 &&
      results.selectors.every(s =>
        VIEW_VALIDATION_SELECTORS[s] ||
        ACCESS_CONTROL_SELECTORS[s] ||
        DEX_CALLBACK_SELECTORS[s]
      );
    if (hasOnlyViewFunctions && !hasCritical) {
      return 'LOW';
    }

    // NEW: DEX aggregator with proper validation should not be HIGH
    const isDexAggregatorWithValidation = this.dexAggregator &&
      this.dexAggregator.isAggregator &&
      (this.dexAggregator.hasFactoryValidation || this.dexAggregator.hasInitCodeHash);

    // DEX aggregator WITHOUT validation is still risky
    const isDexAggregatorNoValidation = this.dexAggregator &&
      this.dexAggregator.isAggregator &&
      this.dexAggregator.riskLevel === 'HIGH';

    // NEW: Pure proxy contracts should be marked as PROXY, not vulnerable
    if (this.proxyPattern && this.proxyPattern.isProxy) {
      // If it's a known proxy pattern with hardcoded implementation, it's safe
      if (this.proxyPattern.implementation && this.proxyPattern.implementation !== 'dynamic (storage-based)') {
        return 'PROXY';
      }
      // Storage-based proxies could be upgradeable - mark as LOW unless other issues
      if (this.proxyPattern.implementation === 'dynamic (storage-based)') {
        return hasCritical ? 'MEDIUM' : 'LOW';
      }
    }

    // If entry-guarded, downgrade severity
    if (hasEntryGuard) {
      if (hasCritical) {
        return 'MEDIUM';  // Was CRITICAL, but entry guard protects
      } else if (highCount >= 2) {
        return 'MEDIUM';
      } else if (highCount === 1) {
        return 'LOW';
      } else {
        return 'LOW';
      }
    }

    // DEX aggregator with proper callback validation - not exploitable
    if (isDexAggregatorWithValidation && !hasCritical) {
      if (highCount >= 2) return 'MEDIUM';
      return 'LOW';
    }

    // DEX aggregator WITHOUT validation - keep HIGH but note it
    if (isDexAggregatorNoValidation) {
      // This is a real concern - callbacks can be called by anyone
      // But severity depends on whether contract holds tokens
      // For now, mark as HIGH but could be refined with on-chain token balance check
      return 'HIGH';
    }

    // NEW: If CRITICAL but all DELEGATECALLs have hardcoded targets, downgrade
    if (hasCritical && this.allDelegateCallsHaveHardcodedTarget && this.hardcodedAddresses && this.hardcodedAddresses.length > 0) {
      return 'MEDIUM';
    } else if (hasCritical) {
      return 'CRITICAL';
    } else if (zeroAccessControl && hasCalldataCall && results.accessControl.unprotectedCalls > 0) {
      return 'CRITICAL';
    } else if (highCount >= 2) {
      return 'HIGH';
    } else if (highCount === 1 && hasCalldataCall) {
      return 'HIGH';
    } else if (highCount === 1) {
      return 'MEDIUM-HIGH';
    } else if (results.accessControl.unprotectedCalls > 0) {
      return 'MEDIUM';
    } else {
      return 'LOW';
    }
  }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
\x1b[1mArbitrary Call Injection Scanner v4\x1b[0m

Usage:
  node scan-arbitrary-call.js <bytecode-file>
  node scan-arbitrary-call.js <address> --rpc <chain>

Chains: ${Object.keys(RPC_ENDPOINTS).join(', ')}

Features:
  - Detects DELEGATECALL/CALL with user-controlled targets
  - Analyzes access control per CALL (Ownable, AccessControl, custom)
  - Identifies protected vs unprotected external calls
  - Filters out metadata false positives
`);
    process.exit(1);
  }

  let bytecode;
  let address = null;  // Track address for known contract detection
  const input = args[0];
  const rpcIndex = args.indexOf('--rpc');

  if (rpcIndex !== -1 && args[rpcIndex + 1]) {
    if (!input.match(/^0x[0-9a-fA-F]{40}$/)) {
      console.error('Error: Invalid address');
      process.exit(1);
    }
    address = input;  // Save the address for known contract lookup
    let rpcUrl = RPC_ENDPOINTS[args[rpcIndex + 1].toLowerCase()] || args[rpcIndex + 1];
    console.log(`\nFetching ${input} from ${rpcUrl}...`);
    try {
      bytecode = await fetchBytecode(input, rpcUrl);
      if (!bytecode || bytecode === '0x') {
        console.error('Error: No bytecode at address');
        process.exit(1);
      }
    } catch (e) {
      console.error('Error:', e.message);
      process.exit(1);
    }
  } else if (fs.existsSync(input)) {
    bytecode = fs.readFileSync(input, 'utf8').trim();
  } else if (input.match(/^(0x)?[0-9a-fA-F]+$/)) {
    bytecode = input;
  } else {
    console.error('Error: Invalid input');
    process.exit(1);
  }

  bytecode = bytecode.replace(/^0x/, '').replace(/\s/g, '');
  const scanner = new BytecodeScanner(bytecode, address);
  const results = scanner.scan();
  scanner.printReport(results);
}

// Export for module use
module.exports = {
  BytecodeScanner,
  OPCODES,
  ACCESS_CONTROL_SELECTORS,
  DEX_CALLBACK_SELECTORS,
  KNOWN_FACTORIES,
  INIT_CODE_HASHES,
  KNOWN_SAFE_CONTRACTS,
  VIEW_VALIDATION_SELECTORS,
  SELECTOR_RESTRICTED_PATTERNS
};

// Run CLI only when executed directly
if (require.main === module) {
  main().catch(console.error);
}
