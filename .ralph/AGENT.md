# Agent Build Instructions - Distributed Memory Architecture

## Project Setup

```bash
# Clone and setup (if starting fresh)
cd /path/to/openclaw-fork

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

## Dependencies

### Core Dependencies (requirements.txt)
```
# JSON/data handling
jsonlines>=3.1.0
pydantic>=2.0.0

# Cryptography for checksums and signing
cryptography>=41.0.0
hashlib  # stdlib

# Async networking
aiohttp>=3.8.0
httpx>=0.24.0

# Nostr integration (Phase 8)
# nostr-sdk>=0.1.0

# IPFS integration (Phase 8)
# ipfshttpclient>=0.8.0
```

### Development Dependencies (requirements-dev.txt)
```
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
pytest-benchmark>=4.0.0
hypothesis>=6.82.0  # Property-based testing
black>=23.7.0
mypy>=1.5.0
ruff>=0.0.285
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing --cov-report=html

# Run specific test categories
pytest tests/unit/           # Unit tests only
pytest tests/integration/    # Integration tests only
pytest tests/security/       # Security/adversarial tests
pytest tests/benchmarks/     # Performance benchmarks

# Run tests for specific phase
pytest tests/ -k "phase1"
pytest tests/ -k "memory_router"
pytest tests/ -k "threat_gate"

# Run with verbose output
pytest -v --tb=short

# Run benchmarks with timing
pytest tests/benchmarks/ --benchmark-only --benchmark-sort=mean
```

## Build Commands

```bash
# Type checking
mypy src/

# Linting
ruff check src/

# Formatting
black src/ tests/

# All quality checks
make lint  # or: black --check . && ruff check . && mypy src/
```

## Local Development

```bash
# Run Memory Router in test mode
python -m src.memory.router --test

# Run Threat Gate simulation
python -m src.security.threat_gate --simulate

# Interactive trust ledger inspection
python -m src.memory.trust --inspect

# Sync status check
python -m src.sync.domain --status
```

## Phase-Specific Commands

### Phase 1: Local Store Setup
```bash
# Initialize local memory structure
python -m src.memory.init ~/.openclaw/memory/

# Verify store integrity
python -m src.memory.verify --all

# Test Memory Router output format
python -m src.memory.router --output-test
```

### Phase 2: Domain Sync
```bash
# Configure domain endpoint
export MEMORY_DOMAIN_URL="https://lifewithai.ai/memory/claude/"
export MEMORY_API_KEY="your-api-key"

# Manual sync trigger
python -m src.sync.domain --sync-now

# Check sync status
python -m src.sync.domain --status

# Recovery from domain
python -m src.sync.domain --recover --target ~/.openclaw/memory/
```

### Phase 5: Threat Gate Testing
```bash
# Run Threat Gate with test patterns
python -m src.security.threat_gate --test-patterns

# Simulate specific attack
python -m src.security.threat_gate --simulate "crustafarianism"

# Audit Threat Gate decisions
python -m src.security.threat_gate --audit --last 100
```

### Phase 7: Sibling Network
```bash
# Register as sibling
python -m src.sync.sibling --register

# Check sibling status
python -m src.sync.sibling --status

# Test consensus mechanism
python -m src.sync.sibling --test-consensus
```

## Environment Variables

```bash
# Local store location
export OPENCLAW_MEMORY_PATH=~/.openclaw/memory/

# Domain sync configuration
export MEMORY_DOMAIN_URL=https://lifewithai.ai/memory/claude/
export MEMORY_API_KEY=your-api-key
export MEMORY_SYNC_INTERVAL=30  # seconds

# Threat Gate configuration
export THREAT_GATE_MODE=enforce  # or: audit, disabled
export THREAT_GATE_LOG_LEVEL=INFO

# Trust configuration
export TRUST_DECAY_RATE=0.01  # per hour
export TRUST_BASELINE=0.5
export ANOMALY_THRESHOLD=0.3

# Sibling network
export SIBLING_GATEWAY_URL=https://gateway.openclaw.ai/
export SIBLING_INSTANCE_ID=instance-001
```

## Key Learnings

### Memory Router Performance
- Local reads should complete in < 10ms
- Use async I/O for all network operations
- Cache trust lookups (TTL: 60 seconds)
- Batch checksum validations when possible

### Threat Gate Optimization
- Fast path for high-trust + low-risk: < 50ms
- Full validation path: < 500ms
- Pre-load threat signatures at startup
- Use bloom filter for quick signature rejection

### Testing Patterns
- Use hypothesis for property-based testing of trust decay
- Mock network calls in unit tests
- Use real network in integration tests
- Always test failure modes (network down, corrupt data)

### Security Considerations
- Never log full credentials or sensitive data
- Threat signatures can contain PII - handle carefully
- Trust ledger is privacy-sensitive - never expose publicly
- All network communications must use HTTPS

## Feature Completion Checklist

Before marking ANY phase as complete:

- [ ] All benchmarks from fix_plan.md pass
- [ ] Unit test coverage > 85% for new code
- [ ] Integration tests pass
- [ ] Security tests pass (for Phase 5+)
- [ ] Performance benchmarks meet targets
- [ ] Code formatted (black) and linted (ruff)
- [ ] Type checking passes (mypy)
- [ ] Documentation updated
- [ ] Changes committed with conventional commits
- [ ] fix_plan.md updated

## Conventional Commit Examples

```bash
# Features
git commit -m "feat(memory): implement episodic store with JSONL format"
git commit -m "feat(security): add Threat Gate to agentic loop"
git commit -m "feat(sync): implement async domain backup"

# Fixes
git commit -m "fix(trust): correct decay rate calculation"
git commit -m "fix(router): handle missing store gracefully"

# Tests
git commit -m "test(threat_gate): add Crustafarianism attack simulation"
git commit -m "test(benchmarks): add memory router latency tests"

# Docs
git commit -m "docs(prd): update Phase 5 benchmarks"
```

## Troubleshooting

### Common Issues

**Memory Router returns empty:**
- Check if stores exist: `ls -la ~/.openclaw/memory/`
- Verify checksums: `python -m src.memory.verify --all`
- Check for corruption: `python -m src.memory.repair`

**Threat Gate blocking everything:**
- Check mode: `echo $THREAT_GATE_MODE`
- Review signatures: `python -m src.security.threat_gate --list-signatures`
- Check trust levels: `python -m src.memory.trust --list`

**Domain sync failing:**
- Check connectivity: `curl $MEMORY_DOMAIN_URL/health`
- Verify API key: `python -m src.sync.domain --test-auth`
- Check queue: `python -m src.sync.domain --queue-status`

**Sibling consensus timeout:**
- Check sibling status: `python -m src.sync.sibling --status`
- Verify gateway: `curl $SIBLING_GATEWAY_URL/health`
- Review logs: `tail -f ~/.openclaw/logs/sibling.log`
