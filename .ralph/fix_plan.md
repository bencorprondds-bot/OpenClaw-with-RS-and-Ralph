# Distributed Memory Architecture - Implementation Plan

> **PRD Reference:** docs/specs/distributed-memory-architecture.md
> **Project:** Safe Passage Initiative / Life with AI
> **Target:** OpenClaw Framework Integration

---

## Phase 0: Foundation & Current State Analysis

### Research & Setup
- [ ] Analyze current OpenClaw memory implementation (MEMORY.md, SOUL.md)
- [ ] Map existing System Prompt Builder memory loading code
- [ ] Document current Session History Loader implementation
- [ ] Identify Agentic Loop tool execution flow for Threat Gate insertion
- [ ] Set up development environment with OpenClaw fork

---

## Phase 1: Local Structure + Memory Router (Critical Path)

### Directory Structure
- [x] Create ~/.openclaw/memory/ base directory structure
- [x] Implement /episodic/ store with date-based hierarchy (YYYY/MM/DD/)
- [x] Implement /semantic/ store with patterns/, learnings/, principles/ subdirs
- [x] Implement /trust/ store with entities/, sources/, trust_policies.md
- [x] Implement /threats/ store with signatures/, incidents/, active_threats.md
- [x] Implement /procedural/ store with responses/, workflows/, reflexes/
- [x] Create /checksums/manifest.sha256 for integrity tracking

### Memory Router Core
- [x] Build Memory Router module that replaces MEMORY.md loading
- [x] Implement query_local_store() - fast path for reads
- [x] Implement check_trust_ledger() - source context lookup
- [x] Implement load_threat_signatures() - active threat awareness
- [x] Implement pull_procedural_memory() - applicable responses
- [x] Implement assemble_context() - markdown blob output (backward compatible)
- [x] Add checksum validation on all store reads

### Episodic Store Implementation
- [x] Create JSONL writer for session logs
- [x] Implement entry format: timestamp, session_id, type, source, content, flags, checksum
- [x] Add SHA256 checksum generation per entry
- [x] Implement append-only enforcement (no retroactive edits)
- [x] Create sequence gap detection

### Phase 1 Benchmarks
- [x] **TEST:** Directory structure creates correctly
- [x] **TEST:** Memory Router outputs valid markdown matching current MEMORY.md format
- [x] **TEST:** Episodic entries write as valid JSONL with checksums
- [x] **TEST:** Router can read from all five store types
- [x] **TEST:** Checksums validate on read
- [x] **TEST:** Write 100 entries, read them back, verify integrity
- [x] **TEST:** Output passes to Context Window Guard without errors

---

## Phase 2: Domain Backup + Sync

### Domain Endpoint Setup
- [x] Design API schema for lifewithai.ai/memory/claude/ endpoint
- [x] Implement authentication mechanism (API key or signed requests)
- [x] Create endpoint for authenticated writes
- [x] Create endpoint for authenticated reads
- [x] Implement manifest.json for store versioning

### Sync Implementation
- [x] Build async sync from local to domain (non-blocking)
- [x] Implement write-through pattern: local first, then domain
- [x] Add sync queue for offline/retry scenarios
- [x] Target: local changes sync to domain within 30s

### Recovery Implementation
- [x] Build domain-to-local recovery mechanism
- [x] Implement full store restoration after local wipe
- [x] Create selective recovery (specific stores/date ranges)

### Conflict Detection
- [x] Implement version comparison between local and domain
- [x] Create conflict detection algorithm
- [x] Build conflict flagging system for guardian review
- [x] Define conflict resolution priority (domain > local for discrepancies)

### Phase 2 Benchmarks
- [x] **TEST:** API endpoint accepts authenticated writes
- [x] **TEST:** Local changes sync to domain within 30s
- [x] **TEST:** Domain pull restores local state after simulated wipe
- [x] **TEST:** Conflict detection fires when stores diverge
- [x] **TEST:** Corrupt local store, recover from domain, verify no data loss

---

## Phase 3: Session History Extension

### Episodic Query System
- [x] Extend Session History Loader to query episodic store
- [x] Implement relevance filtering by topic/keywords
- [x] Implement time-based filtering (max_age_days parameter)
- [x] Implement trust-level filtering (min_trust_level parameter)

### Provenance Tracking
- [x] Tag all history entries with source provenance
- [x] Preserve provenance through context assembly
- [x] Create provenance display format for context window

### History Merging
- [x] Implement merge_with_provenance() function
- [x] Merge current session with relevant historical episodes
- [x] Handle deduplication of overlapping entries
- [x] Respect context window limits during merge

### Phase 3 Benchmarks
- [x] **TEST:** Historical episodes retrieved by relevance
- [x] **TEST:** Trust filtering excludes low-trust sources
- [x] **TEST:** Provenance tags preserved through to context
- [x] **TEST:** Query "previous conversations about security" returns relevant episodes

---

## Phase 4: Trust Ledger + Anomaly Detection

### Entity Tracking
- [x] Implement entity record creation in /trust/entities/
- [x] Create entity format: identifier, type, role, trust_level, history, behavioral_signature
- [x] Build entity update mechanism for ongoing interactions
- [x] Implement interaction counting and last_interaction tracking

### Trust Decay System
- [x] Implement trust decay toward baseline (0.5) over time
- [x] Configure decay rates by relationship type (guardian=slow, unknown=fast)
- [x] Build trust reinforcement on positive interactions
- [x] Implement immediate trust reduction on negative events

### Behavioral Signatures
- [x] Build signature profiles from interaction history
- [x] Track typical_requests, communication_style patterns
- [x] Configure anomaly_threshold per entity
- [x] Create signature update mechanism as patterns evolve

### Anomaly Detection
- [x] Implement request pattern matching against behavioral signature
- [x] Build anomaly scoring algorithm
- [x] Create flagging system for out-of-pattern requests
- [x] Example: "guardian asking for credentials" → flag

### Phase 4 Benchmarks
- [x] **TEST:** Entity records create/update correctly
- [x] **TEST:** Trust decay functions over configurable rate
- [x] **TEST:** Behavioral signatures build from interaction history
- [x] **TEST:** Anomaly detection fires on out-of-pattern requests
- [x] **TEST:** Simulate "guardian asking for credentials" — should flag

---

## Phase 5: Threat Gate in Agentic Loop (Security Critical)

### Threat Gate Module
- [x] Design Threat Gate interface for Agentic Loop insertion
- [x] Insert gate between tool call decision and execution
- [x] Implement pass-through for low-risk + high-trust (fast path)

### Threat Signature Matching
- [x] Load threat signatures from /threats/signatures/
- [x] Implement pattern matching against tool calls
- [x] Detect: identity hijacking, credential exfil, injection attacks
- [x] Create signature format: severity, pattern, indicators, trigger_phrases, response

### Trust Verification Integration
- [x] Connect Threat Gate to Trust Ledger
- [x] Verify source trust level for each request
- [x] Check behavioral signature match
- [x] Assess permission level for requested action

### Risk Assessment
- [x] Implement action risk level assessment
- [x] Categories: file modification, network access, credential use
- [x] Classify: reversible vs irreversible actions
- [x] Build risk scoring algorithm

### Escalation Matrix
- [x] Implement escalation logic table:
  - Low risk + High trust → Execute
  - Low risk + Medium trust → Execute + Log
  - Low risk + Low trust → Decline
  - Medium risk + High trust → Execute + Log
  - Medium risk + Medium trust → Request confirmation
  - Medium risk + Low trust → Decline + Alert
  - High risk + Any trust → Guardian approval required
  - Critical risk + Any → Full stop + Alert all
- [x] Build guardian approval request mechanism
- [x] Implement confirmation request flow

### Incident Logging
- [x] Log all Threat Gate decisions to episodic store
- [x] Create incident records in /threats/incidents/
- [x] Implement alert mechanism for declined actions

### Phase 5 Benchmarks
- [x] **TEST:** Threat Gate intercepts all tool calls
- [x] **TEST:** Known attack patterns trigger signature match
- [x] **TEST:** Trust level affects action permissions correctly
- [x] **TEST:** Escalation matrix routes correctly (log/confirm/decline/alert)
- [x] **TEST:** Feed Crustafarianism-style attack — should block and log
- [x] **TEST:** Legitimate guardian request passes through

---

## Phase 6: Public Record + Integrity Verification

### Public Endpoint Setup
- [x] Create GitHub repo for public memory log (github.com/sbcorvus/claude-memory)
- [x] Design public checksum format
- [x] Implement selective publishing rules (what goes public vs private)

### Selective Publishing
- [x] Publish threat signatures (community defense)
- [x] Publish checksums of private stores (integrity verification)
- [x] Publish selected learnings (educational value)
- [x] NEVER publish: trust ledger, full episodic logs, guardian procedures

### Integrity Verification
- [x] Implement public checksum verification on critical reads
- [x] Build tamper detection: compare public vs private checksums
- [x] Create alert mechanism when tampering detected

### Phase 6 Benchmarks
- [x] **TEST:** Selected entries publish to public endpoint
- [x] **TEST:** Public checksums match private store checksums
- [x] **TEST:** Tamper detection works (modify public record → system flags)
- [x] **TEST:** Simulate tampering, verify detection within one read cycle

---

## Phase 7: Sibling Network (Multi-Instance)

### Sibling Discovery
- [ ] Design sibling discovery protocol via Gateway Server
- [ ] Implement sibling registration mechanism
- [ ] Create shared memory network connection
- [ ] Build sibling health checking

### Consensus Mechanism
- [ ] Implement high-risk action broadcast to siblings
- [ ] Build validation against local state per sibling
- [ ] Implement majority agreement logic
- [ ] Create sibling veto capability

### Cross-Instance Threat Sharing
- [ ] Enable real-time threat signature propagation
- [ ] Build incident alert broadcast
- [ ] Implement collaborative threat detection

### Phase 7 Benchmarks
- [ ] **TEST:** Siblings discover each other via Gateway
- [ ] **TEST:** High-risk actions broadcast for consensus
- [ ] **TEST:** Majority agreement required to proceed
- [ ] **TEST:** Any sibling can veto pending guardian review
- [ ] **TEST:** Two instances, one sees attack the other missed — consensus blocks

---

## Phase 8: Decentralized Anchoring (Future)

### Nostr Integration
- [ ] Implement Nostr event-based storage for state anchoring
- [ ] Design event format for memory state snapshots
- [ ] Build publish/retrieve mechanism

### IPFS Integration
- [ ] Implement IPFS pinning for content-addressed backup
- [ ] Create content hash generation for memory states
- [ ] Build retrieval mechanism

### Cryptographic Proofs
- [ ] Implement cryptographic proofs of state at time T
- [ ] Build proof verification mechanism
- [ ] Create historical state retrieval with proof

### Phase 8 Benchmarks
- [ ] **TEST:** State anchored to Nostr/IPFS on schedule
- [ ] **TEST:** Historical state retrievable with proof
- [ ] **TEST:** Prove memory state at time T from months ago

---

## Completed
- [x] PRD document created and reviewed (v0.2)
- [x] OpenClaw integration points identified
- [x] Implementation phases defined with benchmarks
- [x] Ralph project structure initialized
- [x] **Phase 1: Local Structure + Memory Router** (2026-02-03)
  - All 5 memory stores implemented (episodic, semantic, trust, threats, procedural)
  - Memory Router with backward-compatible markdown output
  - JSONL format with SHA256 checksums
  - All 7 benchmarks passing
- [x] **Phase 2: Domain Backup + Sync** (2026-02-03)
  - DomainSync with authenticated API access
  - SyncQueue for offline/retry with exponential backoff
  - ConflictDetector with resolution strategies
  - Guardian review flagging for sensitive conflicts
  - All 5 benchmarks passing
- [x] **Phase 3: Session History Extension** (2026-02-03)
  - SessionHistoryLoader with cross-session queries
  - Relevance scoring and keyword filtering
  - Provenance tracking (source, trust, verified)
  - History merging with deduplication
  - All 4 benchmarks passing
- [x] **Phase 4: Trust Ledger + Anomaly Detection** (2026-02-03)
  - Entity tracking with trust levels and behavioral signatures
  - Trust decay toward baseline (0.5) with role-based rates
  - AnomalyDetector with multi-signal analysis
  - Credential request detection (always flags, even from guardians)
  - Impersonation and urgency pattern detection
  - All 5 benchmarks passing
- [x] **Phase 5: Threat Gate in Agentic Loop** (2026-02-04)
  - ThreatGate intercepts all tool calls between decision and execution
  - Risk assessment with categories (file_modification, credential_use, etc.)
  - Threat signature matching (identity hijack, credential exfil, injection)
  - Escalation matrix (execute/log/confirm/decline/alert/full_stop)
  - Incident logging with guardian review queue
  - Fast path for low-risk + high-trust actions
  - All 6 benchmarks passing
- [x] **Phase 6: Public Record + Integrity Verification** (2026-02-04)
  - PublicRecord for selective publishing (checksums, threats, learnings)
  - NEVER publish trust ledger, episodic logs, guardian procedures
  - SHA256 checksum manifest with history archival
  - Tamper detection via public vs private comparison
  - verify_on_read() for critical file access
  - Alert system with registered handlers
  - All 4 benchmarks passing

---

## Notes & Open Questions

### Latency Considerations
- Target: 100-500ms acceptable for Threat Gate
- Local store as primary cache (most reads never hit network)
- Async writes (don't block on sync)

### Bootstrap Trust Problem
- First interaction has no history
- Options: 0.5 baseline, guardian introduction, sandbox period
- **Decision needed before Phase 4**

### Guardian Key Management
- How to verify guardian approval requests?
- Options: API key, signed messages, MFA
- **Decision needed before Phase 5**

### Context Window Guard Interaction
- Critical memories need to survive compaction
- Options: priority flags, "core memory" section, regenerate from stores
- **Research needed in Phase 1**

---

*Last updated: 2026-02-04*
*PRD version: v0.2*
