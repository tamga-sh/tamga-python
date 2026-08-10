# tamga-python

Official Python SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Python applications.

> **Status: scaffold.** This repository currently contains project structure, typed stubs, and
> tooling config only — no endpoint or crypto implementation yet. See
> [docs/plans/tamga-python.plan.md](docs/plans/tamga-python.plan.md) for the build plan and current
> progress.

## Install

```bash
pip install tamga-sdk
```

Published to [PyPI](https://pypi.org/project/tamga-sdk/) as `tamga-sdk` (the bare `tamga` name is
taken by an unrelated logging library); the importable package name is `tamga`.

## Quickstart

> ⚠️ **Illustrative only.** The shape below reflects the SDK's planned public API
> (see [`src/tamga/client.py`](src/tamga/client.py)), but method bodies are not implemented yet —
> this snippet will raise `NotImplementedError` if run against the current scaffold.

```python
from tamga import TamgaClient, TamgaConfig

client = TamgaClient(
    TamgaConfig(account_id="your-account-id", host="api.tamga.sh"),
)

result = client.licenses.validate_by_key("YOUR-LICENSE-KEY")

if result.meta.valid:
    print("License is valid:", result.meta.code)
else:
    print("License is not valid:", result.meta.code, result.meta.detail)
```

## Documentation

- [docs/plans/tamga-python.plan.md](docs/plans/tamga-python.plan.md) — this repo's implementation
  plan, architecture, and task checklist.
- [tamga-api `docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md) — the
  authoritative wire-level protocol reference this SDK implements against, including the
  **Known Server-Side Gaps** section describing which documented features are not yet live
  server-side.

## License

MIT — see [LICENSE](LICENSE).
