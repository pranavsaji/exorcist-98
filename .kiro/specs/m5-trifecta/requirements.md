# Spec: m5-trifecta (The Haunted House Map)

An agent is dangerous when one session combines three things: access to
private data, exposure to untrusted content, and a way to send data out (the
"lethal trifecta"). Each MCP server looks harmless alone; together they are a
haunted house. The map shows the rooms and the doors between them.

## REQ-01 Classify capabilities

1. `classifyCapabilities(server)` labels each MCP server and each built-in
   agent ability with any of: `private-data` (filesystem outside the project,
   email, database, password manager, cloud consoles), `untrusted-input`
   (web fetch, search, issues/PRs, email inbox, chat), `exfiltration`
   (HTTP requests to any host, send email/message, create gist/issue/comment,
   upload). Based on the server's package/command name and, when the Shield's
   pin file has its tools, the tool names and descriptions.
2. The rules are data (`definitions/capabilities.yaml`), not code, with a test
   that every rule has an example.

## REQ-02 Detect the trifecta

1. A config (Kiro, Cursor, Claude Code, VS Code MCP files) has a trifecta when
   the union of enabled servers covers all three. New rule EX-023 (high),
   reported once per config file with the servers that form each leg.
2. Auto-approved tools on any leg raise it to critical.

## REQ-03 Map

1. `exorcist map [dir]` prints the three legs and which servers sit on each.
2. The web results window gets a "Haunted House Map" view when a scan found MCP
   configs: an inline SVG of three rooms (Vault of Secrets, Open Door,
   Escape Tunnel) with each server as a labelled ghost in its room(s), lines
   for a complete trifecta, and a plain-text list for screen readers. Severity
   still never by colour alone.
3. The Haunted Repo gains a defanged MCP config that forms a trifecta.

## Property-based tests

- PBT-TRI-01: adding a server never removes a leg; removing all servers on one
  leg always clears EX-023.
- PBT-TRI-02: server order never changes the result.
