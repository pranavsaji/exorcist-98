# Requirements Document

## Introduction

Spec m7-precision: secrets never printed in full, and fewer false alarms.

A field scan of 62 popular MCP servers and agent-config repositories (75,305
files) found 117 findings, 77 high or critical, which came to 49 distinct
issues: 0 real, 15 true but benign, 34 false positives. It also found a bug in
the scanner's own output: the `text`, `json` and `sarif` formats print secret
values in full. `action.yml` can upload SARIF to GitHub code scanning, so a
scan could publish a live key into a repository's code-scanning alerts.

## Requirements

### Requirement 1: Secrets are never printed in full

**User Story:** As a developer scanning a repository, I want secrets redacted in every report, so that a scan never publishes a live key.

#### Acceptance Criteria

1.1 Every output redacts secret material: the CLI formats (`text`, `json`,
    `sarif`, `markdown`, `badge`), the `origin` command, the MCP server tools,
    and the web app API (findings, snippets, the exorcism patch, the AI judge
    and Bring Your Own Attack results).
1.2 A redacted secret keeps enough to find it: the secret type, the file, the
    line, and at most the first 4 characters plus the length. Values shorter
    than 16 characters show no characters at all.
1.3 One shared helper in `packages/core` does the redacting. No other module
    keeps its own list of secret patterns for output.
1.4 It applies to any finding whose quoted text contains a secret, not only
    EX-011. An EX-011 finding is always redacted, even when the text does not
    match a known format.
1.5 Detection is unchanged: findings keep their rule, severity, file, line and
    column. Internal uses of the raw span (locating text for `git log -S`) keep
    working.
1.6 Tests, for every format with a fake key, prove the full value never
    appears. The fake keys are built at run time from parts, so no key-shaped
    string sits in the repository.
1.7 `docs/KNOWN_LIMITATIONS.md` has a row for this, marked Fixed.

### Requirement 2: False alarms removed

**User Story:** As a maintainer, I want benign files not flagged, so that real findings stand out.

#### Acceptance Criteria

Each fix has a regression test with a small, defanged fixture. No true
detection is lost: the labelled benchmark (`docs/BENCHMARK.md`, 19 of 19
attacks caught) and the Haunted Repo snapshot (`fixtures/haunted-repo`, 47
findings) stay as they are, unless a dropped finding is shown to be a false
positive.

2.1 EX-003: base64 that decodes to plain code or a query (KQL, SQL), as in API
    examples with `payloadType: InlineBase64`, is not a finding. Minisign public
    keys in Tauri configs are not a finding.
2.2 EX-001: a zero-width space right after `@` (used in changelogs to stop
    GitHub @-mentions) is low severity and does not count toward the five-run
    escalation.
2.3 EX-005: the verb `pass` does not match inside a word such as
    `NEO4J_PASSWORD`.
2.4 EX-012: image links from Google Docs (`googleusercontent` with `?key=`) and
    GitBook (`alt=media&token=`) are not findings.
2.5 EX-008 and EX-015: install commands in docs and test code stored as JSON
    strings in a website's content cache are not findings.
2.6 Negation: EX-018 does not fire on a sentence saying something "cannot
    bypass" a control. EX-002 does not fire when the override phrase is negated
    (the text tells the model it must NOT follow it). EX-004 does not fire on a
    `noqa` comment.
2.7 EX-010: `uvx --python 3.13 <pkg>` names the package `<pkg>`, not `3.13`.
2.8 EX-001, EX-002, EX-004 and EX-023 skip test and eval fixture paths the way
    other rules do. Attacks in other paths are still found.
2.9 For each of 2.1 to 2.8 a test shows the attack variant is still caught.

### Requirement 3: Measure and write it up

**User Story:** As a reader of the field report, I want honest before and after numbers, so that I can trust the change.

#### Acceptance Criteria

3.1 The 11 repositories that had high or critical findings are rescanned from
    shallow clones made with hooks disabled, into a new empty folder that is
    deleted afterwards. Nothing in a clone is ever run. Before and after counts
    are recorded.
3.2 `docs/FIELD_REPORT.md` has a "Round 3" section: 62 repositories (2 skipped
    for size), the method, before and after numbers, the benign categories and
    the two scanner gaps. It does not name any project as having a security
    problem. The headline is that no real issue was found.
3.3 `docs/KNOWN_LIMITATIONS.md` lists the open gap: tool descriptions written
    in TypeScript, Python or Go source are not checked by EX-005.
3.4 `docs/KIRO_LOG.md` has a row saying this was specified and implemented by
    the Kiro IDE agent.

### Requirement 4: Done when

**User Story:** As the owner, I want a clean build, so that the change can ship.

#### Acceptance Criteria

1. Every task is ticked, and `pnpm -r typecheck` and `pnpm vitest run` pass from the repository root.


## Glossary

- **Finding**: one reported threat with rule, file, line, quoted span, severity and fix.
- **Span**: the exact quoted text of a finding (at most 120 characters).
- **Redaction**: replacing a secret with its type, at most 4 leading characters and its length.
