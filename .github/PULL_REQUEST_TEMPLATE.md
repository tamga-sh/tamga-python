## Summary

<!-- What does this PR do, and why? -->

## Related plan section(s)

<!-- e.g. Section E (License Checkout Crypto) — see docs/plans/tamga-python.plan.md -->

## Checklist

- [ ] `uv run ruff check .` passes
- [ ] `uv run ruff format --check .` passes
- [ ] `uv run mypy src/` passes
- [ ] `uv run pytest --cov=tamga --cov-fail-under=80` passes
- [ ] Tests were written alongside the implementation (TDD), not bolted on after
- [ ] If this touches `src/tamga/crypto/`, `src/tamga/checkout/`, or `src/tamga/proof.py`: a
      `security-reviewer` pass was requested and CRITICAL/HIGH findings addressed (see
      `CONTRIBUTING.md` and `docs/plans/tamga-python.plan.md` Section 4)
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] Plan checkboxes updated in `docs/plans/tamga-python.plan.md`, with an inline note for any
      deviation from the plan's literal wording

## Test plan

<!-- How did you verify this works? -->
