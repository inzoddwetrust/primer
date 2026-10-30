# pridem

pridem is the deploy machine of the Primer project: a Python 3.12 package that is
installed on every box of every project and brings the box to the state described
by the stacks' `primer.yaml` files and the box passport. The repository holds the
contracts, the parts the machine is built from and its first verbs,
`pridem version` and `pridem status`:

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
- `pridem/verbs/` -- the verbs: each an argument schema and a run, shared by
  the CLI and, later, the Panel's queue; `version` prints the installed
  version, `status` takes the box's lock, recovers runs that ended without a
  verdict and writes its own verdict with no steps;
- `pridem/cli.py` -- the command line turned into a verb's arguments
  (`pridem [--json] <verb>`); an unknown verb, option or argument and a busy
  box are refused before anything runs: exit 1, stderr, no verdict;
- `install.sh` -- the only shell file: the bootstrap of a box in five actions
  (host check; packages, `sops` by version and sha256; the pinned clone; a venv
  without an index from `wheels/` plus the pridem wheel; the links). In the
  repository it is a template with five pins -- tag, commit, the wheel's sha256,
  the repository and the wheel's address -- and refuses until they are set;
- `contract/schema/` -- the JSON Schema of each contract, exported from the
  models and checked against them by tests;
- `tests/` -- unit tests, the probes of each task (`test_probe_DM_*`) and the
  fences in `tests/fences/` (import direction, `subprocess` outside
  `runner.py`; they cover `pridem/`, `tests/` and `tier3/`);
- `tier3/` -- the tier 3 probes, run on the runner against the installed
  machine; tier 1 does not collect them.

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

The passport tests decrypt with the real tools: `age` (apt) and `sops` at the
version and sha256 pinned in `install.sh` must be on `PATH` before `pytest`.

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
each after the same recipe, and `shellcheck` over the tracked `*.sh` files; the
`pytest` job installs `age` and `sops` by the pin of `install.sh` first.
Actions are pinned by commit SHA. The workflow can also be started manually with
the `planted` input, which plants a failure in the `pytest` job; that run must
be red.

Tier 3 (`.github/workflows/tier3.yml`) runs on every push to `main` too: the
`ubuntu-24.04` runner is a single-use box. Docker and Python outside the system
one are removed first; the wheel is built from the pinned backend
(`requirements-build.lock`); `install.sh` gets this run's pins -- the pushed
commit under a temporary tag `v{__version__}` in a local bare clone, the wheel
by `file://` -- and installs the machine as on a box; then the `tier3/` probes
run as root against `/usr/local/bin/pridem`.

A release (`.github/workflows/release.yml`) is a tag `v{__version__}` on the
first parent of `main`. Tier 1 runs on the tag's commit first; then the wheel
is built and the GitHub Release gets two assets: the wheel and `install.sh`
with its pins set to the tag, its commit, the wheel's sha256 and the GitHub
addresses.
