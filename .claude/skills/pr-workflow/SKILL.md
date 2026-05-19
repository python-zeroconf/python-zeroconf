---
name: pr-workflow
description: Create pull requests for python-zeroconf/python-zeroconf. Use when creating PRs, submitting changes, or preparing contributions.
allowed-tools: Read, Bash, Glob, Grep
---

# python-zeroconf PR Workflow

When creating a pull request for `python-zeroconf/python-zeroconf`,
follow these steps. Repo-wide conventions live in
[CLAUDE.md](../../../CLAUDE.md); this skill summarises the parts
that matter at PR-creation time.

## 1. Create branch from origin/master

The default branch is `master`, not `main`. `origin` already
points at `python-zeroconf/python-zeroconf` — there is no fork in
this workflow. Always re-fetch first so the branch is based on
the latest `master`:

```bash
git fetch origin
git checkout -b <branch-name> origin/master
```

If you accidentally branch from `main`, `gh pr create` will fail
because the base branch does not exist.

## 2. There is no PR template

`python-zeroconf` does not ship a `.github/PULL_REQUEST_TEMPLATE.md`
— PR bodies are free-form. Aim for a body that looks roughly like:

```
## Summary
<1–3 sentence prose description of what changed and why>

## Details
<bullets explaining the non-obvious parts: RFC sections cited,
performance characteristics measured, edge cases handled>

## Test plan
- [ ] <how you verified the change>
- [ ] <new tests added under tests/ — point at the file>
```

Cite the relevant RFC section (RFC 6762 / RFC 6763) for any
behaviour change that affects packet contents or timing —
reviewers shouldn't have to reverse-engineer why a constant moved
or a probe interval changed.

## 3. PR title conventions

PRs are squash-merged, so the PR title becomes the commit on
`master`. Only the PR title is linted (by the `pr-title` CI job
running `amannn/action-semantic-pull-request`); per-commit
messages on the PR branch are not checked.

- **Conventional Commits prefix is required on the PR title.**
  Pick from: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`,
  `build`, `ci`, `chore`, `style`, `revert`. The
  `feat`/`fix`/`perf` prefixes show up in the release-notes;
  `chore*` and `ci*` are excluded by semantic-release
  (`exclude_commit_patterns` in `pyproject.toml`), so use those
  for housekeeping.
- **Imperative-mood subject.** "fix: handle empty answer", not
  "fix: handled empty answer".
- **Lowercase first character after the prefix** (enforced by
  `subjectPattern: ^(?![A-Z]).+$`).
- **No `Co-Authored-By` trailers from automated agents.**
- **One logical change per PR.** Let pre-commit run (ruff
  lint + format, mypy, flake8, codespell, cython-lint,
  pyupgrade). If a hook auto-fixes something, re-stage and
  re-commit.

## 4. Cython / `.pxd` discipline

If the PR touches any module listed in `TO_CYTHONIZE`
(`build_ext.py`):

- Update the sibling `.pxd` in the same commit if you changed a
  `cdef class` layout or a `cpdef`/`cdef` signature.
- Do not hand-edit the in-tree `.c` files; the build regenerates
  them, and they're excluded from sdist (`exclude = ["**/*.c"]`
  in `pyproject.toml`).
- Verify the extension still builds locally:
  `REQUIRE_CYTHON=1 poetry install` (re-installs in-place,
  failing loudly if Cython rejects anything).
- Verify it still works without the extension:
  `SKIP_CYTHON=1 poetry install && poetry run pytest tests/`.

## 5. Push and create the PR

```bash
git push -u origin <branch-name>
gh pr create --repo python-zeroconf/python-zeroconf --base master \
  --title "<conventional-commit subject>" \
  --body-file /tmp/pr-body.md
```

Always pass the body via `--body-file`, never `--body "..."` with
shell-escaping — Markdown backticks, asterisks, and angle
brackets must pass through verbatim.

The PR title is what gets enforced — it becomes the squash-merge
commit subject on `master`, so it has to parse as a Conventional
Commit on its own. Per-commit messages on the branch are not
linted.

## 6. After the PR is open

CI runs three jobs:

- `lint` — `pre-commit/action`. If pre-commit passed locally
  this passes too.
- `pr-title` — `amannn/action-semantic-pull-request`. Validates
  the PR title against Conventional Commits. If it fails, fix
  the title in the GitHub UI or with `gh pr edit --title "..."`;
  the workflow re-runs on the edit, no push needed.
- `test` — the full pytest matrix across CPython 3.10–3.14,
  3.14t (free-threaded), and PyPy 3.10, on Linux + macOS +
  Windows. The free-threaded entry is the canary for unguarded
  shared-state bugs; failures there are often genuine even when
  the GIL-enabled rows pass.

CodSpeed also runs on PRs (`CodSpeedHQ/action`) and posts a
benchmark delta as a check. A regression there is signal — if
the PR is a perf change, the comment is the evidence; if not, a
red CodSpeed check usually means the hot path picked up an extra
Python-level branch and wants a second look.
