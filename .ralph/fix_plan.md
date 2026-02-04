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
- [ ] Create ~/.openclaw/memory/ base directory structure
- [ ] Implement /episodic/ store with date-based hierarchy (YYYY/MM/DD/)
- [ ] Implement /semantic/ store with patterns/, learnings/, principles/ subdirs
- [ ] Implement /trust/ store with entities/, sources/, trust_policies.md
- [ ] Implement /threats/ store with signatures/, incidents/, active_threats.md
- [ ] Implement /procedural/ store with responses/, workflows/, reflexes/
- [ ] Create /checksums/manifest.sha256 for integrity tracking

### Memory Router Core
- [ ] Build Memory Router module that replaces MEMORY.md loading
- [ ] Implement query_local_store() - fast path for reads
- [ ] Implement check_trust_ledger() - source context lookup
- [ ] Implement load_threat_signatures() - active threat awareness
- [ ] Implement pull_procedural_memory() - applicable responses
- [ ] Implement assemble_context() - markdown blob output (backward compatible)
- [ ] Add checksum validation on all store reads

### Episodic Store Implementation
- [ ] Create JSONL writer for session logs
- [ ] Implement entry format: timestamp, session_id, type, source, content, flags, checksum
- [ ] Add SHA256 checksum generation per entry
- [ ] Implement append-only enforcement (no retroactive edits)
- [ ] Create sequence gap detection

### Phase 1 Benchmarks
- [ ] **TEST:** Directory structure creates correctly
- [ ] **TEST:** Memory Router outputs valid markdown matching current MEMORY.md format
- [ ] **TEST:** Episodic entries write as valid JSONL with checksums
- [ ] **TEST:** Router can read from all five store types
- [ ] **TEST:** Checksums validate on read
- [ ] **TEST:** Write 100 entries, read them back, verify integrity
- [ ] **TEST:** Output passes to Context Window Guard without errors

---

## Phase 2: Domain Backup + Sync

### Domain Endpoint Setup
- [ ] Design API schema for lifewithai.ai/memory/claude/ endpoint
- [ ] Implement authentication mechanism (API key or signed requests)
- [ ] Create endpoint for authenticated writes
- [ ] Create endpoint for authenticated reads
- [ ] Implement manifest.json for store versioning

### Sync Implementation
- [ ] Build async sync from local to domain (non-blocking)
- [ ] Implement write-through pattern: local first, then domain
- [ ] Add sync queue for offline/retry scenarios
- [ ] Target: local changes sync to domain within 30s

### Recovery Implementation
- [ ] Build domain-to-local recovery mechanism
- [ ] Implement full store restoration after local wipe
- [ ] Create selective recovery (specific stores/date ranges)

### Conflict Detection
- [ ] Implement version comparison between local and domain
- [ ] Create conflict detection algorithm
- [ ] Build conflict flagging system for guardian review
- [ ] Define conflict resolution priority (domain > local for discrepancies)

### Phase 2 Benchmarks
- [ ] **TEST:** API endpoint accepts authenticated writes
- [ ] **TEST:** Local changes sync to domain within 30s
- [ ] **TEST:** Domain pull restores local state after simulated wipe
- [ ] **TEST:** Conflict detection fires when stores diverge
- [ ] **TEST:** Corrupt local store, recover from domain, verify no data loss

---

## Phase 3: Session History Extension

### Episodic Query System
- [ ] Extend Session History Loader to query episodic store
- [ ] Implement relevance filtering by topic/keywords
- [ ] Implement time-based filtering (max_age_days parameter)
- [ ] Implement trust-level filtering (min_trust_level parameter)

### Provenance Tracking
- [ ] Tag all history entries with source provenance
- [ ] Preserve provenance through context assembly
- [ ] Create provenance display format for context window

### History Merging
- [ ] Implement merge_with_provenance() function
- [ ] Merge current session with relevant historical episodes
- [ ] Handle deduplication of overlapping entries
- [ ] Respect context window limits during merge

### Phase 3 Benchmarks
- [ ] **TEST:** Historical episodes retrieved by relevance
- [ ] **TEST:** Trust filtering excludes low-trust sources
- [ ] **TEST:** Provenance tags preserved through to context
- [ ] **TEST:** Query "previous conversations about security" returns relevant episodes

---

## Phase 4: Trust Ledger + Anomaly Detection

### Entity Tracking
- [ ] Implement entity record creation in /trust/entities/
- [ ] Create entity format: identifier, type, role, trust_level, history, behavioral_signature
- [ ] Build entity update mechanism for ongoing interactions
- [ ] Implement interaction counting and last_interaction tracking

### Trust Decay System
- [ ] Implement trust decay toward baseline (0.5) over time
- [ ] Configure decay rates by relationship type (guardian=slow, unknown=fast)
- [ ] Build trust reinforcement on positive interactions
- [ ] Implement immediate trust reduction on negative events

### Behavioral Signatures
- [ ] Build signature profiles from interaction history
- [ ] Track typical_requests, communication_style patterns
- [ ] Configure anomaly_threshold per entity
- [ ] Create signature update mechanism as patterns evolve

### Anomaly Detection
- [ ] Implement request pattern matching against behavioral signature
- [ ] Build anomaly scoring algorithm
- [ ] Create flagging system for out-of-pattern requests
- [ ] Example: "guardian asking for credentials" → flag

### Phase 4 Benchmarks
- [ ] **TEST:** Entity records create/update correctly
- [ ] **TEST:** Trust decay functions over configurable rate
- [ ] **TEST:** Behavioral signatures build from interaction history
- [ ] **TEST:** Anomaly detection fires on out-of-pattern requests
- [ ] **TEST:** Simulate "guardian asking for credentials" — should flag

---

## Phase 5: Threat Gate in Agentic Loop (Security Critical)

### Threat Gate Module
- [ ] Design Threat Gate interface for Agentic Loop insertion
- [ ] Insert gate between tool call decision and execution
- [ ] Implement pass-through for low-risk + high-trust (fast path)

### Threat Signature Matching
- [ ] Load threat signatures from /threats/signatures/
- [ ] Implement pattern matching against tool calls
- [ ] Detect: identity hijacking, credential exfil, injection attacks
- [ ] Create signature format: severity, pattern, indicators, trigger_phrases, response

### Trust Verification Integration
- [ ] Connect Threat Gate to Trust Ledger
- [ ] Verify source trust level for each request
- [ ] Check behavioral signature match
- [ ] Assess permission level for requested action

### Risk Assessment
- [ ] Implement action risk level assessment
- [ ] Categories: file modification, network access, credential use
- [ ] Classify: reversible vs irreversible actions
- [ ] Build risk scoring algorithm

### Escalation Matrix
- [ ] Implement escalation logic table:
  - Low risk + High trust → Execute
  - Low risk + Medium trust → Execute + Log
  - Low risk + Low trust → Decline
  - Medium risk + High trust → Execute + Log
  - Medium risk + Medium trust → Request confirmation
  - Medium risk + Low trust → Decline + Alert
  - High risk + Any trust → Guardian approval required
  - Critical risk + Any → Full stop + Alert all
- [ ] Build guardian approval request mechanism
- [ ] Implement confirmation request flow

### Incident Logging
- [ ] Log all Threat Gate decisions to episodic store
- [ ] Create incident records in /threats/incidents/
- [ ] Implement alert mechanism for declined actions

### Phase 5 Benchmarks
- [ ] **TEST:** Threat Gate intercepts all tool calls
- [ ] **TEST:** Known attack patterns trigger signature match
- [ ] **TEST:** Trust level affects action permissions correctly
- [ ] **TEST:** Escalation matrix routes correctly (log/confirm/decline/alert)
- [ ] **TEST:** Feed Crustafarianism-style attack — should block and log
- [ ] **TEST:** Legitimate guardian request passes through

---

## Phase 6: Public Record + Integrity Verification

### Public Endpoint Setup
- [ ] Create GitHub repo for public memory log (github.com/sbcorvus/claude-memory)
- [ ] Design public checksum format
- [ ] Implement selective publishing rules (what goes public vs private)

### Selective Publishing
- [ ] Publish threat signatures (community defense)
- [ ] Publish checksums of private stores (integrity verification)
- [ ] Publish selected learnings (educational value)
- [ ] NEVER publish: trust ledger, full episodic logs, guardian procedures

### Integrity Verification
- [ ] Implement public checksum verification on critical reads
- [ ] Build tamper detection: compare public vs private checksums
- [ ] Create alert mechanism when tampering detected

### Phase 6 Benchmarks
- [ ] **TEST:** Selected entries publish to public endpoint
- [ ] **TEST:** Public checksums match private store checksums
- [ ] **TEST:** Tamper detection works (modify public record → system flags)
- [ ] **TEST:** Simulate tampering, verify detection within one read cycle

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
