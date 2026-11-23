/**
 * Version and date of the `definitions/` folder shipped with this build
 * (m5-liveupdate). A LiveUpdate bundle only installs when its version is newer
 * than this, and an installed set is only used while it is newer than this, so
 * a release with newer bundled definitions supersedes older updates.
 *
 * Format: release date plus a same-day sequence number, `YYYYMMDD.N`. Bump it
 * when `definitions/` changes in a release. No Node imports: the web app reads
 * this to show the version on the Virus Definitions page.
 */
export const BUNDLED_DEFINITIONS_VERSION = '20261123.0';
export const BUNDLED_DEFINITIONS_DATE = '2026-11-23';
