# TraceLens End-to-End Overview

This document explains how TraceLens works from start to finish in simple words.

## What TraceLens Does

TraceLens checks one or more repositories (backend/frontend) and finds:

- security and architecture issues
- contract mismatches between frontend and backend
- standards violations based on user-selected standards
- mandatory flow gaps (for important security checks)

It then builds a single report with prioritized issues and suggested fixes.

## High-Level Flow

TraceLens works in stages, like a pipeline:

1. Input and standard selection
2. Repo loading and project detection
3. Static code parsing
4. Cross-service graph building
5. Contract validation
6. Mandatory flow analysis
7. Standards evidence collection
8. Rule engine issue generation
9. False-positive filtering and normalization
10. Final report generation

---

## 1) Input and Standard Selection

User gives:

- repository URLs or local paths
- optional selected standard (from `.data/standards`)
- runtime options (if runtime checks are enabled)

TraceLens resolves the selected standard into concrete check strategies and evidence markers.

## 2) Repo Loading and Project Detection

TraceLens clones/loads repositories and identifies repo type:

- backend
- frontend
- mixed

It also discovers useful repo metadata (paths, ports, entry points).

## 3) Static Code Parsing

### Backend (FastAPI parser)

TraceLens parses Python AST and extracts endpoint data:

- method and path
- request/response schema details
- dependencies and decorator signals
- try/except presence
- auth and ownership semantic signals

Recent mechanism improvements also include:

- service call tracing (service-layer auth/ownership checks)
- endpoint intent metadata (expects body, file response, status code literal)

### Frontend (React parser)

TraceLens extracts API calls:

- URL and resolved URL
- HTTP method
- payload fields and headers
- environment variable usage

## 4) Cross-Service Graph Building

TraceLens matches frontend calls to backend endpoints using:

- method compatibility
- canonical path similarity
- host/port hints
- normalized path logic

This produces a call graph:

- matched calls
- unmatched calls
- external calls

## 5) Contract Validation

For each matched frontend-backend pair, TraceLens checks:

- wrong HTTP method
- missing required fields
- extra fields
- type mismatches
- missing backend schema (with fallback protections)

## 6) Mandatory Flow Analysis

TraceLens runs flow rules from the mandatory flow catalog (for example):

- authn flow
- authz flow
- ownership flow
- validation flow
- response contract flow
- rate limit flow
- error handling flow

Each endpoint gets status per flow:

- covered
- missing
- ambiguous
- not applicable

## 7) Standards Evidence Collection

If user selected a standard, TraceLens checks code against those selected styles.

Examples:

- auth style = dependency injection
- authz model = RBAC
- response contract = response model
- logging library = structlog
- API layer pattern = RTK Query

Violations are converted into `standards_violation_*` issues.

## 8) Rule Engine Issue Generation

Rule engine combines:

- contract issues
- mandatory flow missing items
- standards violations
- additional heuristic rules (for example IDOR risk, insecure defaults)

It creates normalized issue objects with:

- type
- severity
- description
- evidence
- impact
- fix
- confidence

## 9) False-Positive Filtering and Normalization

TraceLens applies multiple filters to reduce noise:

- style-based reconciliation
- cross-category checks
- sanity checks for known exceptions
- deduplication for repeated service-wide issues

This stage is important to avoid over-reporting.

## 10) Final Report Generation

TraceLens returns:

- summary (counts, severity distribution)
- issue list (critical/high/medium)
- standards compliance section
- flow coverage insights

The report is what user sees in PDF/UI.

---

## Simple Mental Model

Think of TraceLens as a 4-part system:

1. **Understand code** (parsers + AST)
2. **Connect systems** (frontend-backend graph + contract checks)
3. **Judge quality/security** (mandatory flows + standards)
4. **Produce actionable output** (issues + fixes + confidence)

If any one stage is weak, false positives increase.  
If all stages are aligned, report accuracy becomes much better.

---

## Why This Design Works

- AST parsing makes detection more semantic than plain text matching.
- Standard resolution keeps checks aligned to user-selected styles.
- Mandatory flows ensure critical security basics are always checked.
- Multi-layer filtering reduces false positives in real-world projects.

## One-Line Summary

TraceLens reads code deeply, connects frontend and backend behavior, checks both mandatory security flows and user-selected standards, then returns a filtered, prioritized issue report.
