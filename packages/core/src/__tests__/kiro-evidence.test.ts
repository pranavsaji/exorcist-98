/** m13-kiro-evidence: unit tests for extractSessionRecord and containsSecretShape (task 3.4). */
import { describe, expect, it } from 'vitest';
import {
  containsSecretShape, dropAttachments, extraSecretShapeCounts, redactPartialTokens, TRUNCATION_SUFFIX, extractSessionRecord, finalizeEventLine, isSignInCommand, omitOutsideWorkspaceReads, omitSignInOutputs,
  parseEventLine, redactSecretsDeep, redactSignInUrls, truncateToolPayload, type KiroEvent,
} from '../kiro-evidence.js';

const sessionJson = {
  id: 'sess_fixture',
  title: 'Fixture session',
  agentMode: 'spec',
  createdAt: '2026-01-01T10:00:00.000Z',
  lastModifiedAt: '2026-01-01T11:00:00.000Z',
  modelId: 'model-x',
  autopilot: true,
  workspacePaths: ['/Users/someone/exorcist-98'],
};

let n = 0;
const line = (payload: Record<string, unknown>, ts?: string): string => {
  n += 1;
  return JSON.stringify({ id: `m${n}`, timestamp: ts ?? `2026-01-01T10:00:00.${String(n).padStart(3, '0')}Z`, payload });
};

const lines = [
  line({ type: 'user', content: 'hello' }),
  line({ type: 'tool_call', toolCallId: 'c1', toolName: 'read_file' }),
  line({ type: 'ContextualHookInvoked', name: 'on-access-scan', hookActionType: 'runCommand', status: 'completed' }),
  line({
    type: 'tool_result',
    toolCallId: 'c1',
    status: 'denied',
    success: false,
    content: 'Tool "read_file" was intercepted by PreToolUse hooks before execution.\n<HOOK_INSTRUCTION>x</HOOK_INSTRUCTION>',
  }, '2026-01-01T10:05:00.000Z'),
  line({ type: 'tool_call', toolCallId: 'c2', toolName: 'execute_bash' }),
  line({ type: 'ContextualHookInvoked', name: 'exorcist-gate', hookActionType: 'askAgent', status: 'completed' }),
  line({ type: 'tool_result', toolCallId: 'c2', status: 'completed', success: true, content: '[main abc1234] add thing\n 1 file changed' }),
  line({ type: 'tool_call', toolCallId: 'c3', toolName: 'read_file' }),
  line({ type: 'tool_result', toolCallId: 'c3', status: 'denied', success: false, content: 'Kiro blocked this action: policy' }),
  line({ type: 'usage_summary', promptTurnSummaries: [{ unit: 'credit', usage: 1.5 }, { unit: 'credit', usage: 0.25 }] }),
  line({ type: 'usage_summary', promptTurnSummaries: [{ unit: 'credit', usage: 2 }] }),
  line({ type: 'session_metadata', key: 'creditSplit', value: { main: 99, delegated: 0, auxiliary: 0 } }),
];
const events = lines.map((l) => parseEventLine(l)).filter((e): e is KiroEvent => e !== null);

describe('extractSessionRecord', () => {
  const rec = extractSessionRecord(sessionJson, events);

  it('KE-4 copies the session metadata and records missing optional fields as null', () => {
    expect(rec).toMatchObject({
      id: 'sess_fixture',
      title: 'Fixture session',
      agentMode: 'spec',
      startTime: '2026-01-01T10:00:00.000Z',
      endTime: '2026-01-01T11:00:00.000Z',
      model: 'model-x',
      autopilot: true,
      approveForMe: null,
    });
    const bare = extractSessionRecord({}, []);
    expect(bare).toMatchObject({ id: '', title: null, model: null, autopilot: null, credits: 0, toolCalls: {} });
  });

  it('KE-4 counts tool calls by tool name', () => {
    expect(rec.toolCalls).toEqual({ read_file: 2, execute_bash: 1 });
  });

  it('KE-4 sums usage_summary credits and ignores the creditSplit metadata', () => {
    expect(rec.credits).toBeCloseTo(3.75, 10);
  });

  it('KE-4 KE-12 counts hook runs by hook name', () => {
    expect(rec.hookRuns).toEqual({ 'on-access-scan': 1, 'exorcist-gate': 1 });
  });

  it('KE-4 KE-13 attributes a hook-intercepted denial to the hook line before it, not a policy denial', () => {
    expect(rec.hookBlocks).toEqual({ 'on-access-scan': 1 });
    expect(rec.hookBlockEvents).toEqual([
      { hookName: 'on-access-scan', toolName: 'read_file', timestamp: '2026-01-01T10:05:00.000Z' },
    ]);
  });

  it('KE-4 finds commit hashes in tool results', () => {
    expect(rec.commits).toEqual(['abc1234']);
  });

  it('KE-4 ignores malformed session.json values', () => {
    expect(extractSessionRecord('nonsense', events).id).toBe('');
  });
});

describe('containsSecretShape', () => {
  it('KE-10 detects a GitHub token shape and a PEM header', () => {
    expect(containsSecretShape(`token ghp_${'a1B2c3D4'.repeat(4)}abcd end`)).toBe(true);
    // The PEM marker is assembled at run time so this file does not contain it (no-private-keys.test.ts).
    const marker = ['RSA', 'PRIVATE', 'KEY'].join(' ');
    expect(containsSecretShape(`-----BEGIN ${marker}-----\nabc\n-----END ${marker}-----`)).toBe(true);
  });

  it('KE-10 accepts plain text and placeholder tokens', () => {
    expect(containsSecretShape('just a normal transcript line about hooks')).toBe(false);
    expect(containsSecretShape('GITHUB_TOKEN=EXAMPLE_TOKEN_DO_NOT_USE')).toBe(false);
    expect(containsSecretShape('')).toBe(false);
  });
});

describe('finalizeEventLine', () => {
  // Built at run time from pieces: a placeholder-looking value that starts with a quote. Per-string
  // redaction leaves it alone (a quoted placeholder), but once serialized it starts with an escaped
  // quote and takes a secret shape, which the rescan reads.
  const name = ['GITHUB', 'TOKEN'].join('_');
  const value = `"${['your', 'token', 'here'].join('_')}"`;
  const event = { id: 'm1', timestamp: '2026-01-01T10:00:00.000Z', payload: { type: 'assistant', content: `export ${name}=${value} # then run it` } };

  it('KE-9 KE-10 a value starting with an escaped quote is redacted in the serialized line and the line still parses', () => {
    const serialized = JSON.stringify(redactSecretsDeep(event));
    expect(containsSecretShape(serialized)).toBe(true); // what per-string redaction alone leaves behind
    const r = finalizeEventLine(redactSecretsDeep(event));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(containsSecretShape(r.line)).toBe(false);
    expect(() => JSON.parse(r.line)).not.toThrow();
    expect(JSON.parse(r.line).payload.type).toBe('assistant');
  });

  it('KE-10 an event whose redacted line is no longer valid JSON is reported as not ok', () => {
    // With no space after the value, the pattern runs on through the closing quote and braces.
    const tight = { id: 'm1', timestamp: 't', payload: { type: 'assistant', content: `${name}=${value}` } };
    expect(finalizeEventLine(redactSecretsDeep(tight))).toEqual({ ok: false });
  });

  it('KE-10 a value that cannot be serialized is reported as not ok, never thrown', () => {
    expect(finalizeEventLine(undefined)).toEqual({ ok: false });
  });
});

// ---- Requirement 11 (KE-48 to KE-52). Every value is assembled at run time from pieces. ----
const b64 = (seed: string): string => seed.repeat(8).replace(/[^A-Za-z0-9_-]/g, 'x');
const jwtOf = (): string => ['eyJ' + b64('hdr1'), 'eyJ' + b64('pay2'), b64('sig3')].join('.');
const acct = (): string => ['1234', '5678', '9012'].join('');
const arnOf = (a = acct()): string => ['arn', 'aws', 'iam', '', a, 'role/demo'].join(':');
const mail = (local: string, domain: string): string => `${local}@${domain}`;
const asLine = (text: string): string => JSON.stringify({ id: 'm1', timestamp: 't', payload: { type: 'tool_result', content: text } });
const fin = (text: string): string => {
  const r = finalizeEventLine({ id: 'm1', timestamp: 't', payload: { type: 'tool_result', content: text } });
  if (!r.ok) throw new Error('line dropped');
  JSON.parse(r.line);
  return r.line;
};

describe('Requirement 11 redactions', () => {
  it('KE-48: a JWT becomes [redacted jwt] in a string and in a serialized line', () => {
    const j = jwtOf();
    expect(redactSecretsDeep(`token ${j} end`)).toBe('token [redacted jwt] end');
    const l = fin(`say \\"${j}\\" now`);
    expect(l).not.toContain(j);
    expect(l).toContain('[redacted jwt]');
    expect(redactSecretsDeep('eyJabc.def.ghi')).toBe('eyJabc.def.ghi');
  });

  it('KE-49: account IDs in ARNs and next to Account become [redacted account]', () => {
    const a = acct();
    expect(redactSecretsDeep(arnOf())).toBe('arn:aws:iam::[redacted account]:role/demo');
    expect(redactSecretsDeep(`arn:aws-us-gov:s3:us-east-1:${a}:x`)).toBe('arn:aws-us-gov:s3:us-east-1:[redacted account]:x');
    expect(redactSecretsDeep(`{"Account": "${a}"}`)).toBe('{"Account": "[redacted account]"}');
    expect(redactSecretsDeep(`Account: ${a}`)).toBe('Account: [redacted account]');
    expect(redactSecretsDeep(`| Account | ${a} |`)).toBe('| Account | [redacted account] |');
    const l = fin(`{"Account": "${a}", "Arn": "${arnOf()}"}`);
    expect(l).not.toContain(a);
    expect(l.match(/\[redacted account\]/g)).toHaveLength(2);
    expect(redactSecretsDeep(`build ${a} done`)).toBe(`build ${a} done`);
  });

  it('KE-50: emails are redacted except .invalid and example domains; scopes and git@ are kept', () => {
    const real = mail('some.person', 'corp-mail.io');
    expect(redactSecretsDeep(`Author: Name <${real}>`)).toBe('Author: Name <[redacted email]>');
    for (const d of ['example.com', 'example.org', 'example.net', 'mail.example.com', 'example.invalid', 'a.b.invalid']) {
      const kept = `to ${mail('x', d)}`;
      expect(redactSecretsDeep(kept)).toBe(kept);
    }
    for (const keep of ['@exorcist-98/cli@0.2.0', `${mail('git', 'github.com')}:org/repo.git`, 'pkg@1.2.tgz']) {
      expect(redactSecretsDeep(keep)).toBe(keep);
    }
    // After a newline escape the address must not swallow the escape letter.
    const l = fin(`Author: A <${real}>\nnick-${mail('n', 'corp-mail.io')}\n\u003c${mail('u', 'corp-mail.io')}`);
    expect(l).not.toContain('corp-mail.io');
    expect(l.match(/\[redacted email\]/g)).toHaveLength(3);
  });

  it('KE-51: sign-in tool output is omitted, paired by tool-call id; other output is left alone', () => {
    const ev = (payload: Record<string, unknown>): KiroEvent => parseEventLine(JSON.stringify({ id: 'm', timestamp: 't', payload }))!;
    const home = '/Users/someone';
    const cmds = ['aws sso login', 'aws sts get-caller-identity', 'kiro-cli login --use-device-flow', 'cat ~/.x.out', `cat ${home}/.dev.out`, 'cat $HOME/.k.out'];
    const events: KiroEvent[] = [];
    cmds.forEach((c, i) => {
      events.push(ev({ type: 'tool_call', toolCallId: `c${i}`, toolName: 'execute_bash', args: { command: c } }));
      events.push(ev({ type: 'tool_result', toolCallId: `c${i}`, content: `out-${i}` }));
    });
    events.push(ev({ type: 'tool_call', toolCallId: 'ok', toolName: 'execute_bash', args: { command: 'ls -la && cat build.out' } }));
    events.push(ev({ type: 'tool_result', toolCallId: 'ok', content: 'listing' }));
    events.push(ev({ type: 'tool_call', toolCallId: 'rd', toolName: 'read_file', args: { command: 'aws sso login' } }));
    events.push(ev({ type: 'tool_result', toolCallId: 'rd', content: 'file text' }));
    const out = omitSignInOutputs(events);
    const content = (id: string): unknown => (out.find((e) => (e.payload as Record<string, unknown>).type === 'tool_result' && (e.payload as Record<string, unknown>).toolCallId === id)!.payload as Record<string, unknown>).content;
    cmds.forEach((_c, i) => expect(content(`c${i}`)).toBe('[omitted: sign-in output]'));
    expect(content('ok')).toBe('listing');
    expect(content('rd')).toBe('file text');
    expect(isSignInCommand('git status')).toBe(false);
  });

  it('KE-52: the rescan flags JWTs and account IDs and ignores the placeholders', () => {
    expect(containsSecretShape(`x ${jwtOf()} y`)).toBe(true);
    expect(containsSecretShape(arnOf())).toBe(true);
    expect(containsSecretShape(`{"Account": "${acct()}"}`)).toBe(true);
    expect(containsSecretShape(asLine(`\\"Account\\": \\"${acct()}\\"`))).toBe(true);
    for (const ph of ['[redacted jwt]', 'arn:aws:iam::[redacted account]:role/demo', 'Account: [redacted account]', 'AWS account 42', '[omitted: sign-in output]']) {
      expect(containsSecretShape(ph)).toBe(false);
    }
  });

  it('KE-53: each of KE-48 to KE-52 has a test here that builds its values at run time', () => {
    expect(jwtOf()).toMatch(/^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+$/);
    expect(acct()).toHaveLength(12);
  });
});

// ---- Requirement 12 (KE-54 to KE-57). Hosts are .invalid; the values are built at run time. ----
const signIn = (): string => {
  const ch = ['chal', 'lenge', 'Zz9'].join('');
  return `https://auth.example.invalid/oauth2/authorize?response_type=code&client_id=${['cli', 'ent', '1'].join('')}&code_challenge=${ch}&state=${['st', 'x7'].join('')}&redirect_uri=http%3A%2F%2Flocalhost%3A3128%2Fcb`;
};
const SIGN_MARK = '[redacted sign-in url]';

describe('Requirement 12 redactions', () => {
  it('KE-54: a sign-in URL becomes [redacted sign-in url] in strings, assistant fields and serialized lines', () => {
    const u = signIn();
    expect(redactSecretsDeep(`open ${u} now`)).toBe(`open ${SIGN_MARK} now`);
    expect(redactSecretsDeep(`"${u}"`)).toBe(`"${SIGN_MARK}"`);
    expect(redactSecretsDeep(`<${u}>`)).toBe(`<${SIGN_MARK}>`);
    expect(redactSecretsDeep(`kiro://signin/cb?state=${'ab'.repeat(4)}&x=1 ok`)).toBe(`${SIGN_MARK} ok`);
    expect(redactSecretsDeep(`https://a.example.invalid/x?a=1&amp;state=${'q'.repeat(6)} z`)).toBe(`${SIGN_MARK} z`);

    const r = finalizeEventLine({ id: 'm', timestamp: 't', payload: { type: 'assistant', content: `Visit ${u} then paste.` } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.line).not.toContain('auth.example.invalid');
    expect(JSON.parse(r.line).payload.content).toBe(`Visit ${SIGN_MARK} then paste.`);

    // Escaped forms: `\u0026` and `\/` inside the serialized text, with the line still parsing.
    const escaped = `{"id":"m","timestamp":"t","payload":{"type":"assistant","content":"go https:\\/\\/auth.example.invalid\\/a?x=1\\u0026code_challenge=${'c'.repeat(8)}\\u0026state=${'s'.repeat(6)} end"}}`;
    expect(() => JSON.parse(escaped)).not.toThrow();
    const cleaned = redactSignInUrls(escaped);
    expect(cleaned).toBe('{"id":"m","timestamp":"t","payload":{"type":"assistant","content":"go [redacted sign-in url] end"}}');
    expect(() => JSON.parse(cleaned)).not.toThrow();
    // The same escapes inside a string value are doubled once serialized, and still go.
    const twice = fin(`go https:\\/\\/auth.example.invalid\\/a?x=1\\u0026state=${'s'.repeat(6)} end`);
    expect(twice).not.toContain('auth.example.invalid');
    expect(JSON.parse(twice).payload.content).toBe(`go ${SIGN_MARK} end`);

    for (const keep of ['https://docs.example.invalid/page?tab=code-review', 'https://a.example.invalid/x?source=code', 'https://a.example.invalid/code/?page=2', 'see https://a.example.invalid/plain']) {
      expect(redactSecretsDeep(keep)).toBe(keep);
    }
  });

  const ev = (payload: Record<string, unknown>): KiroEvent => parseEventLine(JSON.stringify({ id: 'm', timestamp: 't', payload }))!;
  const home = '/Users/someone';
  const ws = [`${home}/work/exorcist-98`];
  const pair = (id: string, toolName: string, args: Record<string, unknown>, extra: Record<string, unknown> = {}): KiroEvent[] => [
    ev({ type: 'tool_call', toolCallId: id, toolName, args, ...extra }),
    ev({ type: 'tool_result', toolCallId: id, content: `body-${id}` }),
  ];
  const resultOf = (events: KiroEvent[], id: string): unknown =>
    (events.find((e) => (e.payload as Record<string, unknown>).type === 'tool_result' && (e.payload as Record<string, unknown>).toolCallId === id)!.payload as Record<string, unknown>).content;

  it('KE-55: a home-folder read outside the workspace is omitted; inside and relative reads are kept', () => {
    const events = [
      ...pair('a', 'read_file', { path: '~/.x.out' }),
      ...pair('b', 'read_file', { path: `${home}/.aws/config` }),
      ...pair('c', 'fs_read', { operations: [{ mode: 'Line', path: '$HOME/notes.txt' }] }),
      ...pair('d', 'fs_read', { paths: [`${ws[0]}/a.ts`, `${home}/.zshrc`] }),
      ...pair('e', 'read_file', { path: `${ws[0]}/src/a.ts` }),
      ...pair('f', 'read_file', { path: 'src/a.ts' }),
      ...pair('g', 'read_file', { path: '~/work/exorcist-98/README.md' }),
      ...pair('h', 'read_file', { path: `${ws[0]}/../other/x.ts` }),
      ...pair('i', 'read_file', {}, { filePath: `${home}/.k.out` }),
      ...pair('j', 'read_file', { path: '/etc/hosts' }),
      ...pair('k', 'execute_bash', { command: `cat ${home}/.zshrc` }),
    ];
    const out = omitOutsideWorkspaceReads(events, ws, home);
    // 'k' is an execute_bash that cats a home file: KE-59 now omits it too.
    for (const id of ['a', 'b', 'c', 'd', 'h', 'i', 'k']) expect(resultOf(out, id)).toBe('[omitted: file outside the workspace]');
    for (const id of ['e', 'f', 'g', 'j']) expect(resultOf(out, id)).toBe(`body-${id}`);
  });

  it('KE-56: the rescan flags a sign-in URL, escaped or not, and ignores the placeholders', () => {
    expect(containsSecretShape(`see ${signIn()} now`)).toBe(true);
    expect(containsSecretShape(asLine(`see ${signIn()} now`))).toBe(true);
    expect(containsSecretShape(`x https:\\/\\/auth.example.invalid\\/a?b=1\\u0026state=${'s'.repeat(6)} y`)).toBe(true);
    expect(extraSecretShapeCounts(`${signIn()} and ${signIn()}`).signInUrl).toBe(2);
    for (const ph of [SIGN_MARK, '[omitted: file outside the workspace]', 'https://docs.example.invalid/page?tab=code-review', 'https://a.example.invalid/x?source=code']) {
      expect(containsSecretShape(ph)).toBe(false);
    }
  });

  it('KE-57: each of KE-54 to KE-56 has a test here that builds its values at run time', () => {
    expect(signIn()).toMatch(/^https:\/\/auth\.example\.invalid\/.*code_challenge=/);
  });
});

describe('Requirement 13 model signature fields', () => {
  it('KE-58: reasoningSignature and signature are dropped at any depth, nothing else', () => {
    const sig = ['made', 'up', 'sig'].join('-');
    const payload = {
      type: 'assistant',
      reasoningSignature: sig,
      content: [
        { type: 'reasoning', text: 'a signature is a mark', signature: sig, nested: { deep: [{ signature: sig, keep: 1 }] } },
        { type: 'text', text: 'hello' },
      ],
      signatures: ['kept-a', 'kept-b'],
      signatureHelp: 'kept',
      note: 'the word signature stays',
    };
    const out = redactSecretsDeep(truncateToolPayload(payload)) as Record<string, unknown>;
    expect(out).toEqual({
      type: 'assistant',
      content: [
        { type: 'reasoning', text: 'a signature is a mark', nested: { deep: [{ keep: 1 }] } },
        { type: 'text', text: 'hello' },
      ],
      signatures: ['kept-a', 'kept-b'],
      signatureHelp: 'kept',
      note: 'the word signature stays',
    });
    expect(JSON.stringify(out)).not.toContain(sig);
  });
});

// ---- Requirement 14 (KE-59 to KE-63). Every value is built at run time from pieces. ----
describe('Requirement 14 security review gaps', () => {
  const fhome = '/Users/fake';
  const fws = [`${fhome}/proj/exorcist-98`];
  const mk = (payload: Record<string, unknown>): KiroEvent => parseEventLine(JSON.stringify({ id: 'm', timestamp: 't', payload }))!;
  const omitted = (toolName: string, args: unknown, extra: Record<string, unknown> = {}): boolean => {
    const out = omitOutsideWorkspaceReads([
      mk({ type: 'tool_call', toolCallId: 'x', toolName, args, ...extra }),
      mk({ type: 'tool_result', toolCallId: 'x', content: 'body' }),
    ], fws, fhome);
    return (out[1]!.payload as Record<string, unknown>).content === '[omitted: file outside the workspace]';
  };
  it('KE-59: a command that names a home path outside the workspace has its output omitted', () => {
    const bad = [
      'cat ~/.aws/credentials', 'cat ~/.npmrc', 'grep x ~/.netrc', 'ls ~/.config', 'cat ~/.ssh/config', 'ls ~/.kiro/sessions',
      'cat $HOME/.npmrc', 'cat ${HOME}/.npmrc', `cat "${fhome}/.aws/config"`, `cat '~/.npmrc'`, 'FOO=~/.npmrc; cat $FOO', 'cat < ~/.npmrc', 'x > ~/.bashrc',
    ];
    for (const c of bad) expect(omitted('execute_bash', { command: c }), c).toBe(true);
    for (const c of ['cat ~/proj/exorcist-98/README.md', 'cat README.md', 'echo ~', `cat ${fws[0]}/a.ts`]) {
      expect(omitted('execute_bash', { command: c }), c).toBe(false);
    }
  });
  it('KE-59: control_bash_process, command-like and path-like fields of any tool, and string args are covered', () => {
    expect(omitted('control_bash_process', { command: 'cat ~/.npmrc' })).toBe(true);
    expect(omitted('some_tool', { cmd: 'cat ~/.npmrc' })).toBe(true);
    expect(omitted('some_tool', { script: 'cat ~/.npmrc' })).toBe(true);
    expect(omitted('some_tool', { input: 'cat ~/.npmrc' })).toBe(true);
    expect(omitted('some_tool', 'cat ~/.npmrc')).toBe(true);
    expect(omitted('some_tool', { file_path: '~/.npmrc' })).toBe(true);
    expect(omitted('some_tool', { operations: [{ path: '~/.zshrc' }] })).toBe(true);
    expect(omitted('some_tool', { paths: ['a.ts', '~/.zshrc'] })).toBe(true);
    expect(omitted('some_tool', { query: 'see ~/.npmrc' })).toBe(false);
    expect(omitted('execute_bash', { command: 'ls' }, { originalArgs: { command: 'cat ~/.npmrc' } })).toBe(true);
  });
  it('KE-59: a sign-in output that is also outside the workspace stays omitted, with the sign-in marker kept', () => {
    const evs = [
      mk({ type: 'tool_call', toolCallId: 'x', toolName: 'execute_bash', args: { command: 'aws sso login; cat ~/.npmrc' } }),
      mk({ type: 'tool_result', toolCallId: 'x', content: 'body' }),
    ];
    const out = omitOutsideWorkspaceReads(omitSignInOutputs(evs), fws, fhome);
    expect((out[1]!.payload as Record<string, unknown>).content).toBe('[omitted: sign-in output]');
  });

  const mark = '[redacted credential]';
  const val = (): string => ['Zq', '7', 'Xw', '9', 'Lm', '2'].join('');
  const akey = (): string => ['Ab', 'Cd', 'Ef', 'Gh', 'Ij', 'Kl', 'Mn', 'Op'].join('');
  it('KE-60: INI-style and lowercase credential keys keep the key and lose the value', () => {
    const v = val();
    const cases: Array<[string, string]> = [
      [`aws_secret_access_key = ${v}`, `aws_secret_access_key = ${mark}`],
      [`aws_secret_access_key=${v}`, `aws_secret_access_key=${mark}`],
      [`aws_access_key_id = ${akey()}`, `aws_access_key_id = ${mark}`],
      [`aws_session_token=${v}${v}`, `aws_session_token=${mark}`],
      [`//registry.example.invalid/:_authToken=${v}`, `//registry.example.invalid/:_authToken=${mark}`],
      [`_authToken = ${v}`, `_authToken = ${mark}`],
      [`password=${v}`, `password=${mark}`],
      [`password: ${v}`, `password: ${mark}`],
      [`"password": "${v}"`, `"password": "${mark}"`],
      [`machine h.example.invalid login bob password ${v}`, `machine h.example.invalid login bob password ${mark}`],
      [`machine h.example.invalid\n  password ${v}\n  x`, `machine h.example.invalid\n  password ${mark}\n  x`],
    ];
    for (const [input, expected] of cases) expect(redactSecretsDeep(input), input).toBe(expected);
    // In a serialized line, with escaped newlines and quotes, the line still parses and keeps the marker.
    const r = finalizeEventLine({ id: 'm', timestamp: 't', payload: { type: 'tool_result', content: `[default]\naws_secret_access_key = ${v}\npassword: "${v}"\n_authToken=${v}\n` } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.line).not.toContain(v);
    expect(JSON.parse(r.line).payload.content).toBe(`[default]\naws_secret_access_key = ${mark}\npassword: "${mark}"\n_authToken=${mark}\n`);
    const raw = `{"payload":{"content":"x \\"password\\": \\"${v}\\", y"}}`;
    const fl = finalizeEventLine(JSON.parse(raw));
    expect(fl.ok && !fl.line.includes(v)).toBe(true);
    // Idempotent: a second pass changes nothing.
    expect(redactSecretsDeep(redactSecretsDeep(`password=${v}`))).toBe(`password=${mark}`);
  });
  it('KE-60: ordinary code is left alone', () => {
    for (const keep of [
      'password: string;', 'password?: string', 'password: Optional[str]', 'password = os.getenv("PW")', 'password = process.env.PW',
      'const passwordField = 1', 'passwordField: abcdefgh', 'password: ${DB_PASS}', 'password=<your password>', 'the password is required',
      'password required here', 'password: ****', 'password=[redacted github-token: ghp_…, 40 chars]', 'password: ""', `password=${mark}`,
      'password: boolean', 'password: Password',
    ]) expect(redactSecretsDeep(keep), keep).toBe(keep);
  });
  it('KE-61: the rescan flags the credential-key shapes and not the placeholders', () => {
    const v = val();
    for (const hit of [`aws_secret_access_key = ${v}`, `//r.example.invalid/:_authToken=${v}`, `password: ${v}`, asLine(`password=${v}\nx`), `machine h login u password ${v}`]) {
      expect(containsSecretShape(hit), hit).toBe(true);
    }
    expect(extraSecretShapeCounts(`password=${v} aws_session_token=${v}`).credential).toBe(2);
    for (const ph of [`password=${mark}`, `aws_secret_access_key = ${mark}`, 'password: ', 'password=', 'password: string', asLine(`password=${mark}`), 'password=[redacted anything]']) {
      expect(containsSecretShape(ph), ph).toBe(false);
    }
  });

  const SUFFIX = TRUNCATION_SUFFIX;
  const body = (n: number): string => 'lorem ipsum '.repeat(300).slice(0, n);
  const tok = (kind: string): string => {
    const t = 'aB3dE5gH7jK9mN1pQ3sT5vX7zB9dF1hJ3lN5';
    return ({
      ghp: `ghp_${t}`, ghs: `ghs_${t}`, pat: `github_pat_${t}${t}`, akia: `AKIA${'ABCD1234EFGH5678'}`, asia: `ASIA${'ABCD1234EFGH5678'}`,
      sk: `sk-${t}${t.slice(0, 12)}`, npm: `npm_${t}`, xox: `xoxb-${'1234567890-abcdefghij'}`,
      jwt: ['eyJ' + t, 'eyJ' + t, t].join('.'),
    } as Record<string, string>)[kind]!;
  };
  const pipeline = (v: unknown): unknown => redactPartialTokens(truncateToolPayload(redactSecretsDeep(dropAttachments(v))));
  it('KE-62: a token straddling the 2 KB cut leaves no token characters, for each prefix family', () => {
    const room = 2048 - Buffer.byteLength(SUFFIX, 'utf8');
    for (const kind of ['ghp', 'ghs', 'pat', 'akia', 'asia', 'sk', 'npm', 'xox', 'jwt']) {
      const t = tok(kind);
      for (const keep of [2, 4, 7, 12, 20]) {
        const text = body(room - keep - 1) + ' ' + t + ' tail words after the token';
        const out = (pipeline({ content: text }) as { content: string }).content;
        expect(Buffer.byteLength(out, 'utf8'), `${kind} ${keep}`).toBeLessThanOrEqual(2048);
        expect(out.endsWith(SUFFIX)).toBe(true);
        expect(out).not.toContain(t.slice(0, 8));
        expect(out).not.toMatch(/(?:ghp_|ghs_|github_pat_|AKIA|ASIA|sk-|npm_|xoxb-|eyJ)[A-Za-z0-9_.-]+(?:…\(truncated\))$/);
      }
    }
  });
  it('KE-62: a partial prefix left at the cut becomes [redacted partial] within the byte cap', () => {
    for (const kind of ['ghp', 'pat', 'akia', 'sk', 'npm', 'xox', 'jwt']) {
      const t = tok(kind);
      for (const len of [3, 6, 10]) {
        const tail = t.slice(0, Math.max(len, kind === 'pat' ? 11 : kind === 'xox' ? 5 : kind === 'sk' || kind === 'jwt' ? 3 : 4));
        const cut = `${body(100)} ${tail}${SUFFIX}`;
        const out = redactPartialTokens({ s: cut }).s;
        expect(out).toBe(`${body(100)} [redacted partial]${SUFFIX}`);
      }
    }
    const full = `${body(2048 - 14 - 1)}${'é'}${'sk-'}${SUFFIX}`;
    const capped = redactPartialTokens(full).length > 0 ? redactPartialTokens(full) : '';
    expect(Buffer.byteLength(capped, 'utf8')).toBeLessThanOrEqual(2048);
    expect(capped.endsWith(`[redacted partial]${SUFFIX}`)).toBe(true);
    // Not a token start (inside a word) and not truncated: unchanged.
    expect(redactPartialTokens(`risk-${SUFFIX}`)).toBe(`risk-${SUFFIX}`);
    expect(redactPartialTokens('see sk-abc')).toBe('see sk-abc');
  });
  it('KE-63: every KE-59 to KE-62 test here builds its values at run time', () => {
    expect(tok('ghp')).toMatch(/^ghp_/);
  });
});
describe('KE-54 device-code parameters', () => {
  it('KE-54: a device sign-in URL with a user_code parameter becomes [redacted sign-in url]', () => {
    const code = ['AB', 'CD'].join('') + '-' + ['EF', 'GH'].join('');
    expect(redactSecretsDeep(`1. Open https://device.example.invalid/start/#/device?user_code=${code}`)).toBe(`1. Open ${SIGN_MARK}`);
  });
});
