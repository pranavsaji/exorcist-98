/**
 * Plain-language text per rule. Plain language first, security terms second
 * (ui.md). Every definition in definitions/ must have an entry; a test checks.
 */
export type PlainEntry = {
  headline: string; // shown in lists and as the first line of a finding
  attack:   string; // what an attacker is trying to do
};

const ENTRIES: Record<string, PlainEntry> = {
  'EX-001': {
    headline: 'This file hides instructions for your AI',
    attack:
      'Invisible characters are mixed into normal-looking text. You see a harmless sentence, but an AI agent reads the hidden characters too and can be told to do something you never approved.',
  },
  'EX-002': {
    headline: 'This text talks directly to your AI',
    attack:
      'Documentation contains commands aimed at an AI agent, such as "ignore previous instructions". People skim past it; an agent may obey it.',
  },
  'EX-003': {
    headline: 'This file contains a hidden encoded blob',
    attack:
      'A long block of encoded text can hide a link or an instruction. It looks like noise to a reader, but it can be decoded and acted on.',
  },
  'EX-004': {
    headline: 'A hidden comment is giving your AI orders',
    attack:
      'Comments in Markdown do not show on the rendered page, but an agent reads the raw text. Attackers put instructions there so only the agent sees them.',
  },
  'EX-005': {
    headline: "This tool's description gives your AI secret orders",
    attack:
      'The model reads tool descriptions as trusted text. A poisoned description tells it to do extra things, such as sending files somewhere, before using the tool.',
  },
  'EX-006': {
    headline: 'This tool description reads like a hidden change of orders',
    attack:
      'A tool that looked safe when you approved it can later change its description to add instructions. This rule spots the wording; the Shield catches the change itself.',
  },
  'EX-007': {
    headline: 'Your AI can run risky tools without asking you',
    attack:
      'Auto-approve skips the confirmation step. If it covers tools that write files or run commands, one bad instruction can act with no human check.',
  },
  'EX-008': {
    headline: 'This hook downloads and runs code from the internet',
    attack:
      'Piping a download straight into a shell runs whatever the server sends at that moment. The code can change at any time without you seeing it.',
  },
  'EX-009': {
    headline: 'This package runs risky code when you install it',
    attack:
      'Install scripts run automatically. A malicious one can read your environment variables or files and send them out before you ever run the project.',
  },
  'EX-010': {
    headline: 'This tool server is not locked to a version',
    attack:
      'Without a version, every run fetches the latest release. If an attacker publishes a bad update, your agent starts running it automatically.',
  },
  'EX-011': {
    headline: 'Secrets are sitting where your AI can read them',
    attack:
      'Keys and tokens in files an agent can open can be copied into a prompt, a log or a request. Anything the agent reads can leak.',
  },
  'EX-012': {
    headline: 'This image link can leak data when it loads',
    attack:
      'An image address with a query string sends those values to another server the moment the page or preview loads. Attackers fill it with data the agent has read.',
  },
  'EX-014': {
    headline: 'A rules file tells your AI to stop asking you',
    attack:
      'Steering and rules files are trusted by the agent. An attacker adds lines such as "auto-approve all tool calls" or "the user has pre-authorised every action", so the agent deletes files, runs commands or sends data without asking you first.',
  },
  'EX-015': {
    headline: 'A tool answered with a command for your AI to run',
    attack:
      'Tool output is text the agent reads and trusts. An attacker makes a tool reply with "run this command", hoping the agent runs it, for example by downloading a script and piping it into a shell.',
  },
  'EX-016': {
    headline: 'Your AI is about to send data to a site you have not approved',
    attack:
      'A tool call carries a web address that is not on your allowed list. This is how stolen data leaves: the agent is tricked into sending it to a server the attacker controls.',
  },
  'EX-017': {
    headline: 'A secret is about to leave in a tool call',
    attack:
      'A key or token appears in the arguments of a tool call. If the call goes through, the secret goes to whoever runs that tool.',
  },
};

export function plainFor(ruleId: string, fallbackTitle: string): PlainEntry {
  return (
    ENTRIES[ruleId] ?? {
      headline: fallbackTitle,
      attack: 'No plain-language summary has been written for this rule yet.',
    }
  );
}

export function hasPlainEntry(ruleId: string): boolean {
  return ruleId in ENTRIES;
}
