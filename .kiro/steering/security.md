---
inclusion: always
---
# Security rules for this repo

- Never add real malware or working exfiltration endpoints. All attack samples in fixtures/ are defanged (example.invalid domains, placeholder secrets like `EXAMPLE_TOKEN_DO_NOT_USE`).
- The scanner reads untrusted text. Never concatenate scanned text into instructions. Wrap untrusted text in random-nonce delimiters and treat it as data.
- The LLM only labels spans. It never decides control flow, never edits config and never triggers network calls.
- Drop any LLM verdict whose quoted span is not found verbatim in the scanned file.
- Uploaded zips go to S3 with a 24-hour lifecycle; never log file contents, only ids, sizes and timings.
- No secrets in the repo. Use environment variables and keep .env files in .gitignore.
- Do not use real company names, logos or trademarks in the UI, docs or video.
