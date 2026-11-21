# CI workflow draft (not enabled)

`ci.yml` here is a draft. GitHub Actions only runs workflows under
`.github/workflows/`, so nothing in this folder executes.

## Why it is parked

The session that wrote it pushes with a token that may lack the `workflow`
scope GitHub requires for any change under `.github/workflows/`. That
permission gap is open; the draft waits here until someone with that scope
enables it.

## What it closes

| Clause | How |
|---|---|
| SEC-A5 (CI half) | `actions/checkout` and `actions/setup-python` pinned to full 40-char commit SHAs; dev tools installed with `pip --require-hashes` from `requirements-dev.lock` |
| VER-1 | `ruff check`, `ruff format --check`, `mypy` (strict, from `pyproject.toml`) and `pytest` all fail the job |
| SEC-6 / SEC-8 (standards) | `permissions: contents: read`; `timeout-minutes: 10` |

## Before enabling

1. **`ruff format --check .` fails on current `main`** (4 files: `examples/gmail/demo.py`,
   `gate/send_gate.py`, `tests/test_hardening.py`, `tests/test_send_gate.py`).
   Run `ruff format .` in its own PR first, or the first CI run is red.
2. Python 3.10–3.12 are untested locally (only 3.13 was available); the
   matrix is what will check them.

## Enabling

```
git mv .github/workflow-drafts/ci.yml .github/workflows/ci.yml
git mv .github/workflow-drafts/requirements-dev.lock requirements-dev.lock
git rm .github/workflow-drafts/README.md
```

Then make `ci / gate` a required check on `main`.

## Regenerating the lock

When `pyproject.toml` dev pins change:

```
uv pip compile pyproject.toml --extra dev --generate-hashes \
  --python-version 3.10 --universal -o requirements-dev.lock
```

Verified on 2026-11-21 with Python 3.13: a fresh venv installed the lock
with `--require-hashes --no-deps`, `pip check` was clean, and `mypy` and
`pytest` (33 passed) ran from it.
