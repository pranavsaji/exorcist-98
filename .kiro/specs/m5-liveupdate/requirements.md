# Spec: m5-liveupdate (signed definition updates)

Every 90s antivirus had a "LiveUpdate" button. New prompt-injection tricks
appear weekly; definitions should not wait for a new release. Updates must be
signed, because a definitions feed is itself a perfect attack channel.

1. A definitions bundle is a tarball of `definitions/*.yaml` plus
   `manifest.json` (version, date, sha256 per file) and `manifest.sig`, an
   Ed25519 signature of the manifest (Node `crypto.sign`/`verify`, no new
   dependencies).
2. `scripts/sign-definitions.ts` builds and signs a bundle with a private key
   read from an environment variable (never committed). The public key is
   embedded in the CLI.
3. `exorcist update [--from <url-or-file>]` downloads (HTTPS only, 2 MB limit,
   15 s), verifies the signature and every hash, validates every YAML with the
   definitions schema, checks the version is newer, then installs into
   `~/.exorcist/definitions/<version>/` atomically. Any failure leaves the
   current definitions untouched.
4. The CLI and Shield prefer the newest verified installed definitions over the
   bundled ones; `exorcist update --status` shows which set is active.
5. The web app's Virus Definitions page shows the definitions version and date.
6. Tests: tampered manifest, tampered file, wrong key, older version, oversize
   download, invalid YAML each fail closed; a good bundle installs.
