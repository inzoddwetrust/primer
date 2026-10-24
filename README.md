# pridem

pridem is the deploy machine of the Primer project: a Python 3.12 package that is
installed on every box of every project and brings the box to the state described
by the stacks' `primer.yaml` files and the box passport. The repository holds the
contracts and the parts the machine is built from; there are no machine verbs yet
(`pridem` prints its version):

- `pridem/stacks/` -- contract 1 (passport) and contract 3 (`primer.yaml`,
  `primer.lock`) as models, rules and loaders; the YAML loader refuses anchors,
  aliases, nesting deeper than 32 and files over 1 MiB before parsing;
- `pridem/report/` -- contract 2 (the verdict): model, rules, codes and renders;
- `pridem/runner.py` -- the only place a process starts, and `FakeRunner`, a
  strict scenario for tests;
- `pridem/steps/base.py`, `pridem/plan.py`, `pridem/events.py` -- the step,
  the plan with restore and finally, step events and log lines;
- `pridem/state.py` -- `state.json`, `history/` and `journal/` of a box under
  one lock;
- `contract/schema/` -- the JSON Schema of each contract, exported from the
  models and checked against them by tests;
- `tests/` -- unit tests, the probes of each task (`test_probe_DM_*`) and the
  fences in `tests/fences/` (import direction, `subprocess` outside
  `runner.py`).

Development environment (Python 3.12 exactly):

```
cd <absolute path>/pridem
python3.12 -m venv .venv
export PATH=<absolute path>/pridem/.venv/bin:$PATH
pip install --no-index --find-links wheels/ --require-hashes -r requirements.lock
pip install --no-deps -e .
pip freeze --exclude-editable > /tmp/runtime.txt && pip install -c /tmp/runtime.txt -e ".[dev]"
ruff check . && ruff format --check . && mypy . && pytest -q
```

Runtime dependencies are declared as ranges in `pyproject.toml`, pinned with
hashes in `requirements.lock` and shipped as wheels in `wheels/`, because boxes
have no access to PyPI. The recipe above installs the runtime exactly as a box
gets it, then the package without dependencies, then the dev tools (pinned `==`
in `pyproject.toml`) constrained to the installed runtime, so a tool that needs
another runtime version fails instead of moving it. A test checks that the
wheels in `wheels/` are exactly the lock's (name, version, sha256) and that the
installed runtime has the lock's versions.

CI runs on every push to `main` (`.github/workflows/ci.yml`, `ubuntu-24.04`,
Python 3.12) as four jobs: `ruff` (lint and format check), `mypy` and `pytest`,
each after the same recipe, and `shellcheck` over the tracked `*.sh` files.
Actions are pinned by commit SHA. The workflow can also be started manually with
the `planted` input, which plants a failure in the `pytest` job; that run must
be red.
