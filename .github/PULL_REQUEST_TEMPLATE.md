## Summary

<!-- What does this PR do, and why? -->

## Checklist

- [ ] `uv run ruff check .` passes
- [ ] `uv run ruff format --check .` passes
- [ ] `uv run mypy src/` passes
- [ ] `uv run pytest --cov=tamga --cov-fail-under=80` passes
- [ ] Tests were written alongside the implementation (TDD), not bolted on after
- [ ] If this touches `src/tamga/crypto/`, `src/tamga/checkout/`, or `src/tamga/proof.py`: a
      `security-reviewer` pass was requested and CRITICAL/HIGH findings addressed (see
      `CONTRIBUTING.md`)
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)

## Test plan

<!-- How did you verify this works? -->
