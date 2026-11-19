# Tasks: m4-polish

- [x] TASK-01 Sound: synthesised cues, muted by default, persisted toggle. (REQ-01)
- [x] TASK-02 Browser-safe reporters, report downloads, SVG badge, `--format badge`. (REQ-02)
- [x] TASK-03 Keyboard window moves, label-in-name fix, axe on every page. (REQ-03)
- [x] TASK-04 `/product` landing page. (REQ-04)
- [x] TASK-05 Tarball fetch replaces git clone; standalone output; deployment rehearsal; Dockerfile. (REQ-05)
- [x] TASK-06 Crew app in its own repository. (REQ-06) Built and tested outside Crew; not yet run in Crew.
- [x] TASK-07 Tests and docs. (REQ-07)

## Results

- 431 unit and property tests pass in 37 files.
- Browser suite: 24 steps, 0 axe violations, run against a standalone copy of
  the server outside the repository, including a real GitHub scan through the
  tarball path.
- GitHub: CI (`test`, `build`, `e2e`) and the Action's `scan` job were green on `07991dc`, which includes the M4 commit.

## Not done here

- Choosing a host and deploying: needs your account (see `docs/DEPLOY.md`).
- The Dockerfile was not built: the Docker daemon was not running.
- The landing page has no LinkedIn link; add yours for the startup bonus.
