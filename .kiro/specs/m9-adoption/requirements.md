# Requirements Document

## Introduction

Spec m9-adoption: make Exorcist 98 easy to adopt on a real team. Source: `TASK-adoption.md`.
Four areas: a baseline and inline suppressions, tool descriptions in server source code,
a warning for stale definitions, and CLI wording found by a review.

## Glossary

- **Baseline**: `.exorcist-baseline.json`, the list of findings a team has accepted for now.
- **Fingerprint**: SHA-256 (first 32 hex characters) of the finding's redacted, whitespace-collapsed span. It never includes the line number.
- **Active finding**: a finding that is neither baselined nor suppressed inline. Only active findings decide the exit code.
- **Directive**: an inline comment of the form `exorcist-ignore EX-012: <reason>`.

## Requirements

### Requirement 1: Baseline

**User Story:** As a team lead, I want to adopt the scanner on an existing repository without fixing everything first, so that the scan fails only on new problems.

#### Acceptance Criteria

1.1 `exorcist baseline [folder]` scans the folder and writes `.exorcist-baseline.json` in it (or at `--output`). It accepts `--definitions` and `--ignore`, and prints how many entries it wrote.
1.2 One entry per current finding: rule id, file (relative path), fingerprint and line. The file holds no span text and no secret, and its entries are sorted so the output is the same for the same findings.
1.3 The fingerprint is computed from the redacted span, so no value derived from a secret is stored.
1.4 `exorcist scan --baseline <file>` reports only findings that are not in the baseline, and prints how many it suppressed. Findings are matched on rule id, file and fingerprint. The line is not compared, so moving a finding to another line does not make it new again.
1.5 A finding whose fingerprint changed is new again. A finding that appears more times than the baseline has entries for it is new for the extra ones.
1.6 A missing, unreadable or invalid baseline file makes `scan` exit 2 with a plain message. It never silently scans without it.
1.7 The GitHub Action has an input `baseline` (a path, default empty) that passes `--baseline` to every scan step.
1.8 The baseline file is validated with zod, and an unknown `version` is refused.
1.9 `exorcist baseline` applies inline suppressions first, so a finding suppressed in source is not also written to the baseline.

### Requirement 2: Inline suppression

**User Story:** As a developer, I want to silence one rule on one line with a written reason, so that an accepted exception is visible in review.

#### Acceptance Criteria

2.1 A directive `exorcist-ignore EX-NNN: <reason>` inside a comment on the same line as a finding, or on the line before it, suppresses that rule's findings on that line. Comment openers recognised: `//`, `#`, `<!--`, `/*`, `--`, `;`. Only the first directive on a line counts.
2.2 The reason is required and must contain a letter or digit once comment closers (`-->`, `*/`) are removed. A directive without a reason suppresses nothing and is listed as rejected.
2.3 EX-001 (hidden characters) and EX-011 (secrets) can never be suppressed inline. Neither can a finding that reports a scan timeout (`isTimeoutFinding`). Such directives are listed as rejected.
2.4 A directive never suppresses a finding that starts at or after its own comment opener on the directive's line. The text of the comment, including its reason, is therefore always scanned in full: a directive cannot hide an attack written inside itself.
2.5 Every inline suppression is reported: rule id, file, line and reason (at most 200 characters, secrets redacted, control and hidden characters shown escaped). Text output lists them under the summary, `json` includes them, and rejected directives are listed with the cause.
2.6 Suppressed findings do not count toward the exit code or `--fail-on`.

### Requirement 3: SARIF suppressions

**User Story:** As a user of GitHub code scanning, I want baselined and suppressed results kept in the report and marked, so that the history is not lost.

#### Acceptance Criteria

3.1 `--format sarif` keeps baselined and suppressed findings as results, each with a `suppressions` array: `kind: "external"` with justification "In the baseline" for a baselined result, and `kind: "inSource"` with the reason as justification for an inline one. Active results have no `suppressions` property.
3.2 `--format json` lists only active findings in `findings` and adds a `suppressed` summary with `baseline` count and the inline list. `markdown` and `badge` use active findings only.
3.3 Exit code is decided by active findings only.

### Requirement 4: Tool descriptions in server source code

**User Story:** As a developer who writes an MCP server in TypeScript, Python or Go, I want its tool descriptions checked, so that a poisoned description is found by a scan and not only at run time.

#### Acceptance Criteria

4.1 For source files, the scanner extracts the description strings of these registrations and checks only those strings with the tool-description checks (EX-005): TypeScript and JavaScript `server.tool(name, "description", ...)` and `registerTool(name, { description: "..." })`; Python `@mcp.tool` and `@server.tool` decorators (with or without arguments) and the docstring of the decorated function, plus `description=` keyword; Go `mcp.NewTool(name, ..., mcp.WithDescription("..."))`.
4.2 A finding points at the line and column of the string in the source file, and its span is the matched text, not the whole string.
4.3 Text outside those strings is not checked by EX-005 in source files. A code comment or a string elsewhere that says "before calling this tool" is not reported.
4.4 Ordinary hints such as "use X before calling this tool" produce no finding. The benchmark gains look-alike benign cases (a set from the field scan: 188 such strings in 62 repositories, none an attack), one per language, and they stay at zero findings.
4.5 A poisoned description in each language is caught by EX-005. The benchmark gains an attack case per language.
4.6 Extraction is linear time: no nested quantifiers, strings are read with a small scanner, and a file is read only up to the existing size limit. Extraction never executes or evaluates the source.
4.7 `docs/KNOWN_LIMITATIONS.md` L-051 is updated to what is covered and what is not (other languages, descriptions built at run time).

### Requirement 5: Stale definitions

**User Story:** As a maintainer, I want a hint when my definitions are old, so that I do not trust a scan made with out-of-date rules.

#### Acceptance Criteria

5.1 `exorcist scan`, `baseline` and `map` print one warning on stderr per run when the definitions in use are more than 30 days old. The warning gives the age in days and says how to update (`exorcist update --from <url-or-file>` or install a newer version).
5.2 The age comes from the active set (`activeDefinitions`: the installed set when it is newer, else the bundled date). With `--definitions` or `EXORCIST_DEFINITIONS` pointing to a custom folder, there is no warning.
5.3 The warning never goes to stdout, so `json`, `sarif`, `markdown` and `badge` output is unchanged.
5.4 No network call is added. The check compares a date with the current date; `now` is injectable for tests.

### Requirement 6: CLI wording

**User Story:** As a user, I want the summary to say true things in good English, so that I can trust it.

#### Acceptance Criteria

6.1 The summary counts only files that have at least one finding ("8 threats in 3 files"), then says how many were scanned ("Scanned 120 files."). Applies to `text` and `markdown`.
6.2 Every count is pluralised correctly: "1 file", "2 files", "1 threat". One shared `plural` helper is used by `scan`, `origin` and the reporters.
6.3 `exorcist init` lists each file once in its summary.
6.4 When `.kiro/settings/mcp.json` has a server whose `autoApprove` contains `"*"`, `init --kiro` warns in plain words that the agent can run every tool of that server without asking, and names the server.
6.5 The text output ends with a verdict line, using the same words as the web app: CLEAN, HAUNTED (medium or low worst) and POSSESSED (high or critical). The mapping lives in `packages/core` and the web app uses it.

### Requirement 7: Quality and documentation

#### Acceptance Criteria

7.1 Every requirement above has at least one test. New pure functions in `packages/core` have fast-check properties where an invariant exists (fingerprint ignores line, a directive never suppresses EX-001 or EX-011, matching is count-aware).
7.2 No secret, and no value derived from one, is written to the baseline, a report or a log. Fake keys in tests are built at run time from parts.
7.3 README and the CLI help describe `baseline`, `--baseline`, directives, and the Action input.
7.4 `docs/KIRO_LOG.md` has a row for this work by the Kiro IDE agent.
7.5 `pnpm -r typecheck` and `pnpm vitest run` pass from the repository root. The benchmark attacks stay caught and the Haunted Repo snapshot is unchanged.
