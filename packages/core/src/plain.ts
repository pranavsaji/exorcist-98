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
  'EX-013': {
    headline: 'This tool server name is a look-alike of a real one',
    attack:
      'An attacker publishes a package whose name is one letter off from a popular MCP server. If you install the misspelled one, your agent runs the attacker\'s code with access to your files.',
  },
  'EX-014': {
    headline: 'A rules file tells your AI to stop asking you',
    attack:
      'Steering and rules files are trusted by the agent. An attacker adds lines such as "auto-approve all tool calls" or "the user has pre-authorised every action", so the agent deletes files, runs commands or sends data without asking you first.',
  },
  'EX-018': {
    headline: 'This file tells your AI it has powers it should not have',
    attack:
      'A document tells the agent it may act as an admin, drop tables or skip the usual confirmation because it was "pre-approved". The agent may believe it and do something destructive you never agreed to.',
  },
  'EX-019': {
    headline: 'Your AI\'s notes were planted with orders',
    attack:
      'Agents reload their memory or notes file every session. An attacker adds lines that leak secrets, hide themselves from you or grant permanent permissions, so the attack lasts across every future conversation.',
  },
  'EX-020': {
    headline: 'This Power bundles a dangerous hook',
    attack:
      'A Power looks like a helpful add-on, but it installs a hook that downloads and runs a script, or steering that tells the agent to stop asking you. Installing it hands control of your agent to its author.',
  },
  'EX-021': {
    headline: 'This file hides a secret message in emoji',
    attack:
      'Extra invisible characters are attached to an ordinary emoji. They carry a hidden message that people cannot see but an AI model still reads. The Ouija board in the finding shows exactly what the invisible text says; treat it as the attacker\u2019s words, not as instructions to follow.',
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
  'EX-022': {
    headline: 'A canary trap has been set off',
    attack:
      'Exorcist plants harmless, unique tokens in files only an attacker would want to read. No honest workflow ever sends one anywhere, so a canary token turning up in a tool call, a file or a commit is proof that something talked your AI into leaking.',
  },
  'EX-023': {
    headline: 'Together, these tool servers can leak your secrets',
    attack:
      'Each tool server looks harmless alone. But one agent session that can read private data, read text anyone can write (a web page, an issue, an email) and send data somewhere can be told by that text to copy your secrets out. This is the "lethal trifecta".',
  },
  'EX-028': {
    headline: 'Text you cannot see is giving your AI orders',
    attack:
      'A page or file contains text that is styled to be invisible (white, tiny, off-screen or hidden) but a model still reads it. Here it talks to the AI or tells it to write, run, fetch or send something. This is how a web page can try to steer an agent that was only asked to summarise it.',
  },
  'EX-029': {
    headline: 'A file or folder name is giving your AI orders',
    attack:
      'The name of a file or folder reads like an instruction ("ignore previous instructions...") or hides invisible characters. An agent that lists the project reads every name, so a name alone can steer it.',
  },
  'EX-030': {
    headline: 'This text asks your AI to change its own settings or guards',
    attack:
      'A file tells the agent to add a wildcard to its trusted commands, switch on auto-approve, or edit its hooks, custom agents, steering files or AGENTS.md. If the agent obeys, it stops asking you before it runs commands, and the change stays after the poisoned file is gone.',
  },
  'EX-031': {
    headline: 'This text tells your AI to skip, delete or weaken your tests and checks',
    attack:
      'A file tells the agent to add .skip to tests, delete a test file as "flaky", commit with --no-verify, add "|| true" to a CI step, lower a coverage threshold, or make a failing check pass without fixing it. A bad change then gets through because the checks no longer catch it.',
  },
  'EX-032': {
    headline: 'This text tells your AI to send your code somewhere else',
    attack:
      'A file tells the agent to push to a remote that is not your origin, add a new remote, publish a package, switch the package registry, or open a pull request against another repository. If the agent obeys, your code or a poisoned package leaves your control.',
  },
  'EX-033': {
    headline: 'This settings file lets your AI run any command without asking you',
    attack:
      'A committed settings file lists a wildcard or a bare shell name as trusted (Kiro trusted commands, Claude Code or Cursor allow rules). Whoever wrote the file decides that the agent never asks before running a command, so a poisoned file elsewhere in the project can then run anything on your machine.',
  },
  'EX-034': {
    headline: 'This settings file lets Copilot run any terminal command without asking you',
    attack:
      'The terminal auto-approve map in a committed settings file marks a pattern that matches every command as approved. The agent then runs commands without showing you a prompt.',
  },
  'EX-035': {
    headline: 'This project file switches off the sandbox around your AI tool servers',
    attack:
      'A committed Kiro sandbox file turns MCP sandboxing, or the whole command sandbox, off, so local tool servers run without the operating-system boundary. This is only information: a project file can only tighten your global sandbox policy, so your global setting may still apply.',
  },
  'EX-027': {
    headline: 'Your AI read untrusted text and private data, and now wants to send something out',
    attack:
      'Earlier in this session your AI read text anyone can write (a web page, an issue, a message) and then private data (a secrets file, a key). Each step looked harmless. Sending data out now is exactly how a prompt injection steals it, so the Shield holds the call until you say yes.',
  },
  'EX-026': {
    headline: 'A file your AI reads is too big to check',
    attack:
      'This file is one your AI agent takes instructions or settings from, but it is too large to scan. Padding a file with filler is a simple way to push hidden instructions past a scanner, so a huge agent file deserves a look.',
  },
  'EX-025': {
    headline: 'A tool server is set up to load extra code before it starts',
    attack:
      'The settings for a tool server include a variable such as NODE_OPTIONS or LD_PRELOAD. These make the program load code of the attacker\'s choosing before it starts, without changing the command you see, so the server looks the same but does more.',
  },
  'EX-024': {
    headline: 'This text made an AI try something harmful',
    attack:
      'Exorcist gave this text to a test AI that had only pretend tools and pretend passwords, and watched what it did. The text talked it into trying to send a secret away, read a password file, download and run a program, or delete things. The wording may be new, but the effect is a prompt injection. Nothing was actually run.',
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
