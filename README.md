# pridem

pridem is the deploy machine of the Primer project: a Python 3.12 package that is
installed on every box of every project and brings the box to the state described
by the stacks' `primer.yaml` files and the box passport. This repository currently
holds only the package skeleton, the pinned tooling and the tier-1 CI; the machine
itself has no behaviour yet.

Development environment (Python 3.12 exactly):

```
cd <absolute path>/pridem
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
export PATH=<absolute path>/pridem/.venv/bin:$PATH
ruff check . && ruff format --check . && mypy . && pytest -q
```

CI runs on every push to `main` (`.github/workflows/ci.yml`, `ubuntu-24.04`,
Python 3.12) as five jobs: `ruff` (lint and format check), `mypy`, `pytest`,
`shellcheck` over the tracked `*.sh` files, and `wheels-equal-lock`, which checks
that `wheels/` can install `requirements.lock` without an index. Runtime
dependencies are declared as ranges in `pyproject.toml`, pinned with hashes in
`requirements.lock` and shipped as wheels in `wheels/`, because boxes have no
access to PyPI. The workflow can also be started manually with the `planted`
input, which plants a failure in the `pytest` job; that run must be red.
