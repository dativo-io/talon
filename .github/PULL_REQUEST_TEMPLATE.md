## Description
<!-- Describe your changes -->

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update

## Checklist
- [ ] `make check` passes (tests + lint + vet)
- [ ] Contribution guidelines in `CONTRIBUTING.md` followed
- [ ] AI usage, if any, follows `AI_ASSISTANCE.md`
- [ ] Tests added/updated (target: 65% overall coverage, goal 70%)
- [ ] Coverage ≥65% for changed packages
- [ ] Docs updated (if user-facing)
- [ ] CHANGELOG.md updated (if user-facing change)
- [ ] Conventional commit messages used
- [ ] OTel spans on significant functions
- [ ] Evidence generated for auditable operations
- [ ] No secrets hardcoded

## Control-plane proof checklist (MVP #265)
- [ ] Which pillar does this strengthen — cost control, reliability, shared policy, session understanding — or the evidence proof layer beneath them?
- [ ] Enforcement happens before the provider/execution where claimed (deny-before-spend, block-before-forward), and the decision leaves signed evidence.
- [ ] Demoable: does this show up in (or at least not break) the north-star demo (#107)?
- [ ] Claims discipline: describes supporting controls and evidence, not regulatory outcomes; target behavior is not documented as shipped; session caps stay described as soft until atomic reservation lands.
- [ ] Boundary discipline: no implication that Talon controls actions it cannot intercept (local shell/filesystem/direct calls).

## Related Issues
<!-- Link related issues: Fixes #123 -->

## Testing
<!-- How did you test this? -->

## Release Note Draft (for user-facing changes)
<!-- Keep this concise and concrete -->
- Problem solved:
- Who should care:
- How to verify:
- Upgrade/migration impact:

## AI Assistance Disclosure
<!-- If AI tooling was used, summarize where and how you validated outputs -->
- AI tooling used: none / <tool names>
- Human verification performed: