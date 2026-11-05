# pridem

pridem is the deploy machine of the Primer project: a Python 3.12 package that is
installed on every box of every project and brings the box to the state described
by the stacks' `primer.yaml` files and the box passport. The repository holds the
contracts, the parts the machine is built from and its verbs:
`pridem install`, `update`, `deploy <ref>`, `doctor`, `reinstall`, `destroy`,
`report <run_id>`, `version`, `status`, `gc`, `ssl renew` and `check`:

- `pridem/stacks/` -- contract 1 (passport) and contract 3 (`primer.yaml`,
  `primer.lock`) as models, rules and loaders; the YAML loader refuses anchors,
  aliases, nesting deeper than 32 and files over 1 MiB before parsing;
- `pridem/report/` -- contract 2 (the verdict): model, rules, codes and renders;
- `pridem/runner.py` -- the only place a process starts (each command the
  leader of its own group, killed with `pridem`, the box lock handed on), and
  `FakeRunner`, a strict scenario for tests;
- `pridem/interrupt.py` -- SIGINT and SIGTERM set a flag the plan and the
  runner read; no exception lands in the plan's code;
- `pridem/steps/base.py`, `pridem/plan.py`, `pridem/events.py` -- the step,
  the plan with restore and finally, step events and log lines;
- `pridem/state.py` -- `state.json`, `history/` and `journal/` of a box under
  one lock;
- `pridem/verbs/` -- the verbs: each an argument schema and a run, shared by
  the CLI and, later, the Panel's queue; `version` prints the installed
  version, `status` takes the box's lock, recovers runs that ended without a
  verdict and writes its own verdict with no steps; `gc` and `ssl renew` run
  one step as their whole plan under the lock (`pridem/steps/gc.py`, the
  clean-up by labels every plan also runs in `finally`; `ssl_renew` in
  `pridem/steps/ssl.py`), and the box's systemd timers run them
  (`pridem/steps/timers.py`); `check` checks a project's repository with no
  box (`pridem/verbs/check.py`, below); `install`, `update`, `deploy`,
  `doctor`, `reinstall` and `destroy` run the plan the machine makes itself
  (`pridem/verbs/plans.py`, `pridem/verbs/deploy.py`, the ladder of
  `destroy` in `pridem/steps/destroy.py`); `report` renders a run's report
  from `history/` and its journal;
- `pridem/cli.py` -- the command line turned into a verb's arguments
  (`pridem [--json] [--timer] <verb> [arguments] [--option ...]`; `--json` may
  follow the verb too); an unknown verb, option or argument and
  a busy box are refused before anything runs: exit 1, stderr, no verdict;
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

## `pridem check` in a project's CI

`pridem check <directory> [<slot>=<directory> ...]` checks a repository of a
project as the machine checks it on a box, by the same functions (protocol
10.1): `primer.yaml` and `primer.lock` by the machine's loaders -- a host of a
product's `egress` must be a row of the list agreed with Primer for that
product (below) --, the compose
file of every stack by the machine's lists (`docker compose config`; the
binary alone, no daemon, and the repository's `.env` is not read), every
compose variable `${VAR:?}` and a key of `env`, and the `primer-package.yaml`
of each package directory given. It writes nothing and needs no box and no
network; its verdict has the form of contract 2 with no journal, exit 0 green,
1 red, 2 when `docker compose` is not found. `--json` prints the verdict.

A workflow of a project, with the machine pinned by its release tag and the
sha256 of its wheel and of its lock (the first tag of the machine is issued by
Primer; `vX.Y.Z` and the sha256 sums below are placeholders):

```yaml
name: primer check
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-24.04  # has docker compose
    env:
      PRIDEM_TAG: vX.Y.Z
      PRIDEM_WHEEL_SHA256: "<sha256 of pridem-X.Y.Z-py3-none-any.whl>"
      PRIDEM_LOCK_SHA256: "<sha256 of requirements.lock at vX.Y.Z>"
    steps:
      - uses: actions/checkout@<commit sha>  # pin actions by commit
      - uses: actions/setup-python@<commit sha>
        with:
          python-version: "3.12"
      - name: pridem, pinned
        run: |
          base=https://github.com/inzoddwetrust/primer
          wheel="pridem-${PRIDEM_TAG#v}-py3-none-any.whl"
          curl -fsSLO "$base/releases/download/$PRIDEM_TAG/$wheel"
          curl -fsSL -o requirements.lock "https://raw.githubusercontent.com/inzoddwetrust/primer/$PRIDEM_TAG/requirements.lock"
          echo "$PRIDEM_WHEEL_SHA256  $wheel" | sha256sum -c --strict
          echo "$PRIDEM_LOCK_SHA256  requirements.lock" | sha256sum -c --strict
          python -m pip install --require-hashes -r requirements.lock
          python -m pip install --no-deps "$wheel"
      - name: pridem check
        run: pridem check .
```

No value and no secret is needed: a repository holds none, and the check gives
every key of `env` a stand-in.

## Packages: mounted or built in

A package slot of `primer.yaml` (contract 3 rule 10) is applied as the product
declares. `apply: runtime`, the default, binds the package read-only into a
service (`mount`) and checks it with the product's `validate` before `up`.
`apply: build` puts it into the build context of a service at a path inside
it:

```yaml
packages:
  skin:
    contract: ">=1,<2"
    apply: build
    build:
      - { service: frontend, path: public/skin }
```

The machine copies the service's build context out of the immutable release
into `/opt/<stack>/contexts/<entry>/<service>`, puts the package there in place
of `path`, and builds the service from it with `PRIMER_EDITION` -- the
passport's edition, one of `editions` -- as its third and last build argument;
no `validate`: the product's build is the package's check, and a build that
fails leaves the old image running. The image is labelled with the edition and
the packages' versions, so another version or edition in the passport is a new
build on the same commit and the same ones none. A package belongs to the stack
whose compose has its service; a service in no stack of the product is a
finding of `build` and `pridem check`. A product's service may not be named
`pridem-*`, `<dependency>-*` or as the alias of another of its stacks on the
machine's network.

## A product's way out

A product has no way out of its box (protocol 4.1). The machine's networks
`pridem` (nginx and the applications of the stacks) and `pridem-egress` are
internal, and the machine's override makes every network of a product's compose
internal too; nginx publishes the ports 80 and 443 through the edge's own
network. A service keeps its networks and reaches the internet itself.

In transition a product declares in `primer.yaml` the external hosts it still
reaches itself (protocol 4.2), by name:

```yaml
egress:
  - zoom.us
  - api.zoom.us
```

Every host must be a row of the list agreed with Primer for that product
(`pridem/stacks/egress.py`: changed by a release of the machine, a new host by
the owner's word); `pridem check` and `build` on the box refuse any other. With
`egress` declared, the box runs the machine's proxy -- squid, pinned by digest,
in the compose project `pridem-egress` -- which lets through `CONNECT` to port
443 of exactly those hosts and refuses the rest; every service of the product
joins `pridem-egress` and gets the proxy's address as `HTTPS_PROXY` and
`https_proxy` (neither may be a key of the product's `env`). An empty `egress`
is a product with no way out and no proxy; the step `egress`
(`pridem/steps/egress.py`) removes one a previous release left.

