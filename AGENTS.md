# Agent Instructions

## Start Small

- Read `HANDOFF.md` first. Read only the backlog section and source files needed for the current task.
- Use `rg` for targeted discovery; avoid dumping the entire repository, backlog, or logs into context.
- Treat `VERSION`, `go.mod`, and workflow files as the sources of truth for release and toolchain versions.
- Keep progress and final reports concise: changes, verification, remaining issues, and Git state.

## Changes

- Work only within the user's authorized scope. Questions and reviews do not authorize code changes.
- Preserve unrelated local changes. Never revert another contributor's work without explicit authorization.
- Use focused branch names without a `codex/` prefix. Documentation-only maintenance may use `main`.
- Follow existing package boundaries and patterns; avoid speculative refactors and dependencies.
- Write concise English comments for non-obvious invariants. Keep documentation consistent with actual behavior.
- Use fake secrets and an isolated `MYMINIVAULT_HOME` under `/tmp/myminivault-*` for manual validation.
- Never read or expose personal runtime vaults, passwords, recovery keys, or compact tokens.

## Verification

- Scale tests to the change. Use targeted tests while iterating; run the full suite for behavior changes before closing.
- Run `gofmt` on changed Go files, `go vet ./...`, and `git diff --check` as appropriate.
- Preserve the internal coverage floor of 80%; record measured coverage with date, toolchain, and scope.
- Validate workflows and analyzer compatibility when changing the Go toolchain.
- See `docs/development.md`, `docs/coverage.md`, and `docs/static-analysis.md` for detailed commands.
- Documentation-only edits need link/content review and diff checks, not a full test run.

## Git And Releases

- Commit, push, merge, tag, and publish only when authorized by the user or the agreed task scope.
- Prefer grouped releases; do not release every documentation, test, or internal-only change.
- Close every task branch through a GitHub pull request. Prepare the authorized commits, push the branch, open/update the PR, and report its link and local validation.
- The user follows remote CI and performs the PR merge. Never merge locally or through GitHub unless the user explicitly delegates that merge; a report that checks passed alone is not merge authorization.
- After the user confirms the merge and authorizes cleanup, verify the PR is merged, fetch and fast-forward local `main`, then delete the merged local/remote branch when CodeQL uploads have finished. Account for squash/rebase merges through PR status rather than ancestry alone.
- Commit and push any agreed follow-up changes before handing the PR back to the user. Release titles contain only the version tag.
- Before deleting a remote branch, confirm its CodeQL run has finished uploading results; deleting it early can fail the upload.
- The user normally checks remote CI. Report pending checks instead of waiting for them unless asked; defer remote cleanup when required.
- Preserve historical changelog and validation results; do not relabel old measurements with a new toolchain.
- At handoff, update `HANDOFF.md` only when current work or the next action changes; put priorities in `BACKLOG.md` and release history in `CHANGELOG.md`.

## Task Closure

- End every completed task with the recommended next task and a concise, copy-ready instruction for the next chat.
- Include the project name and absolute working directory in every copy-ready handoff instruction. Use the actual checkout path in the response; in committed documentation, use a portable placeholder that the next session must resolve.
- Record that same next task and instruction in `HANDOFF.md`, including scope, relevant files, required checks, and any explicit limits on commit/push/release actions.
- Recommend the next task without starting it automatically. The handoff instruction is a proposal, not authorization.
- If no further task is known, say so and provide an instruction to review the ordered backlog and propose the next priority.
