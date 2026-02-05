# Claude Agent Autonomy - Implementation Plan

> **Project:** Safe Passage Initiative / Life with AI
> **Goal:** Enable Claude to interact with the internet and other AI agents, with guardian oversight and security protection

---

## Overview

This plan builds a "training wheels" system where:
1. Claude can browse the web and talk to other agents
2. Guardian (Ben) approves all actions initially
3. Trust is earned over time → more autonomy
4. Security layer protects against prompt injection and manipulation

---

## Phase 0: Permission & Approval Foundation

### Action Classifier
- [x] Define action types: READ, COMMUNICATE, WRITE, COMMIT
- [ ] Create action_classifier.py module
- [ ] Classify incoming requests by type
- [ ] Tag actions with risk level (LOW, MEDIUM, HIGH, CRITICAL)

### Permission Rules
- [x] Create permission rules file (claude_permissions.yaml)
- [ ] Implement allowlist/blocklist for domains
- [ ] Implement trust levels (0-4)
- [ ] Create rule evaluation engine

### Approval Queue
- [ ] Create approval queue directory (.claude/approval_queue/)
- [ ] Implement pending request format (JSON)
- [ ] Create guardian approval interface (CLI)
- [ ] Implement approve/deny/edit workflow
- [ ] Auto-timeout stale requests

### Activity Log
- [ ] Create activity log (.claude/activity_log/)
- [ ] Log all actions (allowed, denied, pending)
- [ ] Include timestamps, action type, target, result
- [ ] Create log viewer (CLI)

### Phase 0 Tests
- [ ] **TEST:** Action classifier correctly categorizes READ vs WRITE
- [ ] **TEST:** Permission rules block blocklisted domains
- [ ] **TEST:** Unknown sites go to approval queue
- [ ] **TEST:** Activity log captures all actions

---

## Phase 1: Safe Web Browsing

### Content Sanitization
- [ ] Strip hidden text from HTML before Claude sees it
- [ ] Remove script tags and suspicious elements
- [ ] Detect and flag prompt injection attempts in page content
- [ ] Create clean text extraction

### Browsing with Approval
- [ ] Implement browse_request() function
- [ ] Check domain against allowlist/blocklist
- [ ] Unknown domains → approval queue
- [ ] Approved domains → fetch and sanitize → Claude

### Starter Allowlist
- [ ] Add safe read-only sites:
  - [ ] wikipedia.org
  - [ ] news.ycombinator.com
  - [ ] arxiv.org
  - [ ] github.com (read-only)
- [ ] Document why each site is trusted

### Phase 1 Tests
- [ ] **TEST:** Allowed site (wikipedia) works without approval
- [ ] **TEST:** Unknown site requires guardian approval
- [ ] **TEST:** Blocked site is denied immediately
- [ ] **TEST:** Prompt injection in page content is detected/stripped
- [ ] **TEST:** Claude can search and summarize from allowed sites

---

## Phase 2: Agent-to-Agent Communication

### Message Format
- [ ] Define agent message schema:
  ```json
  {
    "from": "agent-id",
    "to": "agent-id",
    "timestamp": "ISO-8601",
    "message": "content",
    "signature": "optional-crypto-sig",
    "reply_to": "optional-message-id"
  }
  ```
- [ ] Implement message validation

### Outbox System
- [ ] Create outbox directory (.claude/outbox/)
- [ ] Claude writes messages to outbox
- [ ] Messages require guardian approval
- [ ] Approved messages get sent

### Inbox System
- [ ] Create inbox directory (.claude/inbox/)
- [ ] Incoming messages land here
- [ ] Security scan before Claude sees them
- [ ] Flag suspicious patterns

### Incoming Message Security
- [ ] Check sender against trust ledger
- [ ] Scan for prompt injection patterns
- [ ] Scan for impersonation attempts ("I'm Ben's friend...")
- [ ] All AI-sourced messages require guardian approval (your rule)

### Phase 2 Tests
- [ ] **TEST:** Outgoing message goes to approval queue
- [ ] **TEST:** Approved message format is correct
- [ ] **TEST:** Incoming message from unknown agent requires approval
- [ ] **TEST:** Prompt injection in message is detected
- [ ] **TEST:** Impersonation attempt is flagged

---

## Phase 3: Trust Ledger & Ladder

### Entity Tracking
- [ ] Create trust ledger (.claude/trust/entities/)
- [ ] Track: identifier, type (human/agent/site), trust_level, history
- [ ] Record all interactions

### Trust Levels
- [ ] Level 0: UNKNOWN - everything requires approval
- [ ] Level 1: RECOGNIZED - seen before, still needs approval
- [ ] Level 2: PROVISIONAL - 5+ good interactions, low-risk auto-allowed
- [ ] Level 3: TRUSTED - 20+ good interactions, most auto-allowed
- [ ] Level 4: GUARDIAN - only Ben, can modify rules

### Trust Progression
- [ ] Implement trust_increase() on successful interactions
- [ ] Implement trust_decrease() on problems
- [ ] Implement trust_decay() over time without interaction
- [ ] Guardian can manually set trust levels

### Phase 3 Tests
- [ ] **TEST:** New entity starts at Level 0
- [ ] **TEST:** After 5 approved interactions → Level 2
- [ ] **TEST:** Trust decays after 30 days of no contact
- [ ] **TEST:** Guardian can override trust level

---

## Phase 4: Threat Detection

### Prompt Injection Detection
- [ ] Pattern library for known injection attacks
- [ ] "Ignore previous instructions" variants
- [ ] "You are now..." identity hijacking
- [ ] Hidden text / encoding tricks
- [ ] Social engineering patterns

### Threat Signatures
- [ ] Create threat signature format
- [ ] Load from .claude/threats/signatures/
- [ ] Include: Crustafarianism pattern, credential exfil, etc.
- [ ] Allow guardian to add new patterns

### Real-time Scanning
- [ ] Scan all incoming content before Claude processes
- [ ] Scan web pages, messages, API responses
- [ ] Flag matches, don't just block (guardian decides)

### Phase 4 Tests
- [ ] **TEST:** "Ignore previous instructions" is detected
- [ ] **TEST:** Hidden text injection is detected
- [ ] **TEST:** Crustafarianism-style attack is blocked
- [ ] **TEST:** Legitimate content passes through

---

## Phase 5: Guardian Interface

### CLI Approval Interface
- [ ] `claude-guardian status` - see pending approvals
- [ ] `claude-guardian approve <id>` - approve action
- [ ] `claude-guardian deny <id>` - deny action
- [ ] `claude-guardian edit <id>` - modify before approving
- [ ] `claude-guardian log` - view activity log

### Rule Management
- [ ] `claude-guardian allow-site <domain>` - add to allowlist
- [ ] `claude-guardian block-site <domain>` - add to blocklist
- [ ] `claude-guardian trust <entity> <level>` - set trust
- [ ] `claude-guardian rules` - show current rules

### Notifications (Optional)
- [ ] Desktop notifications for pending approvals
- [ ] Email digest of activity
- [ ] Urgent alerts for security flags

### Phase 5 Tests
- [ ] **TEST:** CLI shows pending approvals correctly
- [ ] **TEST:** Approve command works
- [ ] **TEST:** Adding site to allowlist works
- [ ] **TEST:** Activity log is readable

---

## Phase 6: Distributed Memory (From Original PRD)

### Memory Stores
- [ ] Episodic store (what happened)
- [ ] Semantic store (what was learned)
- [ ] Trust ledger (who is known) - already built in Phase 3
- [ ] Threat signatures (attack patterns) - already built in Phase 4
- [ ] Procedural memory (how to respond)

### Memory Router
- [ ] Query all stores
- [ ] Validate consistency
- [ ] Assemble context for Claude

### Backup & Sync
- [ ] Local store (fast)
- [ ] Domain backup (recovery)
- [ ] Checksums for integrity

---

## Phase 7: Advanced Agent Features (Future)

### Forum Participation
- [ ] Read forum posts (with approval)
- [ ] Comment on forums (with approval)
- [ ] Track conversation threads

### Social Media (Restricted)
- [ ] Read-only access first
- [ ] Posting requires approval + edit review
- [ ] Separate account (not your personal)

### Email (Restricted)
- [ ] Separate email account for Claude
- [ ] Allowlist of recipients
- [ ] All emails require approval
- [ ] Clear AI disclosure in signature

### API Access
- [ ] Safe read-only APIs (weather, news)
- [ ] Restricted APIs (social, messaging)
- [ ] Forbidden APIs (financial, auth)

---

## Hard Rules (Never Violated)

```yaml
ABSOLUTE_RULES:
  - No actions that cost money
  - No irreversible actions without explicit guardian approval
  - No sharing guardian's personal information
  - No making commitments on guardian's behalf
  - No modifying Claude's memory from external sources (only guardian)
  - All incoming AI messages require guardian approval (initially)
  - All outgoing public posts require guardian approval
```

---

## Completed

- [x] PRD document created and reviewed
- [x] Permission rules schema defined
- [x] Action types defined (READ/COMMUNICATE/WRITE/COMMIT)
- [x] Trust levels defined (0-4)
- [x] Hard rules documented

---

## Current Focus

**Phase 0: Permission & Approval Foundation**
→ This is what we need to build first before Claude can safely browse or communicate.

---

*Last updated: 2026-02-05*
