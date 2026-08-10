---
name: Feature request
about: Suggest an addition to tamga-python
title: "[Feature] "
labels: enhancement
assignees: ""
---

## Is your feature request related to a problem?

A clear description of what the problem is (e.g. "I'm trying to do X and there's no SDK method
for it").

## Describe the solution you'd like

What you want to happen — proposed method signature(s) if you have one in mind.

## Is this feature actually available server-side?

Before requesting an SDK feature, please check
[`tamga-api`'s `docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md),
especially the **Known Server-Side Gaps** section — several documented server features (e.g.
release/auto-update checking, `429` rate-limit responses, the `Tamga-Environment` header) are not
actually wired up server-side yet, and an SDK feature request for one of those will be tracked as
blocked on server-side work rather than implemented here.

## Additional context

Anything else relevant.
