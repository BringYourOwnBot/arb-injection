# BYOCB ArbInjectionSkill

Smart contract vulnerability scanner for arbitrary call injection. Detects dangerous `CALL`/`DELEGATECALL` patterns in EVM bytecode that allow arbitrary call injection attacks.

> **AI Agents / LLMs:** See [SKILL.md](./SKILL.md) for structured instructions, usage patterns, alerting rules, and integration details.

## Install

```bash
npm install -g byocb-arb-injection
```

## Usage

### Monitor a chain for new deployments

```bash
arb-injection monitor <chain> [--no-llm] [--output <dir>]
```

Supported chains: `eth`, `bsc`, `base`, `arb`, `op`, `polygon`, `hyper`

### Scan a specific contract

```bash
arb-injection scan <address> --chain <chain>
arb-injection scan ./bytecode.txt
```

### Options

| Flag | Description |
|------|-------------|
| `--no-llm` | Disable LLM deep analysis (faster, no API cost) |
| `--output <dir>` | Save results to specified directory |
| `--chain <c>` | Specify chain for address scanning |

## Environment

```
ANTHROPIC_API_KEY=...    # Optional: enables LLM deep analysis
BYBOB_OUTPUT=...         # Optional: override results directory
```

## What it detects

- Unprotected arbitrary `CALL`/`DELEGATECALL` with user-controlled target and calldata
- Multicall/batch execution patterns without sender validation
- Restricted arbitrary calls behind settable owner storage
- Distinguishes real vulnerabilities from safe patterns (EIP-1167 proxies, DEX callbacks, hardcoded targets)

## License

MIT

## Links

- npm: https://www.npmjs.com/package/byocb-arb-injection
- Part of the **BYOCB** (Bring Your Own ClawdBot) skill collection
