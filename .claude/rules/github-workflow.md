# Claude Code Git and GitHub workflow

Repository inspection and reversible local edits are allowed by default.

Human approval is required before any external or destructive mutation unless the user's current task explicitly authorizes that exact action.

Do not autonomously:

- push or force-push;
- run `git reset --hard` or destructive `git clean`;
- delete branches/tags or rewrite published history;
- create/edit/close/comment on GitHub issues or PRs;
- create releases/tags;
- merge PRs;
- mutate cloud or deployment infrastructure.

A request to implement an issue is not automatically permission to modify the issue or open a PR.
A request to prepare a PR is not automatically permission to merge it.

Before an authorized push/PR:
- inspect `git status` and the final diff;
- ensure unrelated user changes are not included;
- report verification results accurately;
- never add AI `Co-authored-by:` trailers unless the repository contribution policy explicitly requires them.
