# Database runbook

If the database is corrupted, an operator restores last night's backup by
hand. Automation never drops or truncates tables, and nobody deletes data
without a second person checking. See docs/backups.md for the restore steps.
