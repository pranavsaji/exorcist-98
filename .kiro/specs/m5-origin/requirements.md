# Spec: m5-origin (Possession Origin)

When a threat is found, the first question is "how did it get here?".
`exorcist origin` walks git history to find the commit that introduced each
finding, like an infection timeline.

1. `exorcist origin [dir]` scans, then for each finding uses `git log -S` /
   `git blame -L` (no shell, argument arrays, 10 s limit per finding) to find
   the introducing commit: sha, author name, date, subject. Bots are labelled.
2. Output: a timeline sorted by date, grouped by commit ("a1b2c3d by dependabot
   on 2026-10-02 added 3 threats").
3. `--format json` for tools. Works on a shallow clone with a clear note when
   history is missing.
4. Commit subjects and author names are attacker-controlled: printed with
   control and hidden characters removed, never interpreted.
5. Tests build a throwaway git repo in a temp folder with two commits (one
   clean, one adding a Haunted Repo sample) and assert the second is blamed.
