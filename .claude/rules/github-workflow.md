# Claude Code Git and GitHub workflow

Repository inspection and reversible local edits are allowed by default.

## Feature branches: branch, commit, push autonomously

Standing instruction from the maintainer: every new feature, fix or docs change starts on its own branch and Claude Code carries it to the remote without asking.

1. Never edit on `main`. Before the first edit of a new piece of work, create `type/short-name` (`feat/…`, `fix/…`, `docs/…`, `chore/…`, `test/…`) from current `main`.
2. When a coherent step is verified (see `.claude/rules/testing.md`), stage it with explicit paths (`git add -- <files>`), commit with a conventional-commit message, and push the branch (`git push -u origin <branch>` on the first push, `git push` after). Do this at each meaningful checkpoint and at handoff, not only when asked.
3. Before each commit: inspect `git status` and the diff; exclude unrelated, personal or device files and PR body drafts; `git diff --check`; no secrets.
4. If the push fails for an environment reason (no credentials in a sandbox), say so and hand the user the exact `git push` command; do not retry blindly.

The autonomy stops at the branch: opening or editing a PR, merging, tagging, releasing and commenting on issues or PRs still need the user's instruction for that action.

## Everything else needs approval

Human approval is required before any other external or destructive mutation unless the user's current task explicitly authorizes that exact action.

Do not autonomously:

- force-push, or push to `main`;
- run `git reset --hard` or destructive `git clean`;
- delete branches/tags or rewrite published history;
- create/edit/close/comment on GitHub issues or PRs;
- create releases/tags;
- merge PRs;
- mutate cloud or deployment infrastructure.

A request to implement an issue is not automatically permission to modify the issue or open a PR.
A request to prepare a PR is not automatically permission to merge it.

Before any commit, push or PR:
- inspect `git status` and the final diff;
- ensure unrelated user changes are not included;
- report verification results accurately;
- never add AI `Co-authored-by:` trailers unless the repository contribution policy explicitly requires them.
