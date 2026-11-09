"""DM-80: every fetch of ``install.sh`` over the network is tried again.

The script's own definitions -- ``fail``, the ``curl_get`` array, ``fetch`` and
``clone`` -- are cut out of ``install.sh`` (the one shell file; none is added
for the test) and run under ``bash`` through ``SubprocessRunner``:

- ``fetch`` with the real ``curl`` against a server in this process that
  answers 504 once, or always: once -- the file arrives; always -- six tries,
  no file, and the refusal names the address;
- ``clone`` with ``git`` and ``sleep`` replaced on ``PATH`` by a stub that
  fails as told and records its calls: a clone that fails twice arrives on
  the third try, each failed try's directory removed; five failures -- the
  refusal names the repository and the tag.

How ``apt-get`` retries (``Acquire::Retries=5``) is read by the probe of DM-25.
"""

import http.server
import json
import os
import re
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pridem.runner import Stream, SubprocessRunner

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "install.sh"
PAYLOAD = b"the wheel"


def _definitions() -> str:
    """``fail``, ``curl_get``, ``fetch`` and ``clone`` as ``install.sh`` has them."""
    text = INSTALL.read_text(encoding="utf-8")
    parts = [
        re.search(r"^fail\(\) \{\n.*?^\}\n", text, re.M | re.S),
        re.search(r"^curl_get=\(.*?\)\n", text, re.M),
        re.search(r"^fetch\(\) \{.*?^\}\n", text, re.M | re.S),
        re.search(r"^clone\(\) \{.*?^\}\n", text, re.M | re.S),
    ]
    found = [part.group(0) for part in parts if part is not None]
    assert len(found) == 4, "install.sh lost one of fail, curl_get, fetch, clone"
    return "set -euo pipefail\n" + "".join(found)


def _bash(script: str, path: str | None = None) -> tuple[int, list[str]]:
    said: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        said.append(line)

    env = {"PATH": path or os.environ["PATH"], "HOME": os.environ.get("HOME", "/")}
    done = SubprocessRunner().run(
        ["bash", "-c", _definitions() + script],
        expect=(0, 1),
        timeout=120,
        env=env,
        on_line=keep,
    )
    return done.code, said


@contextmanager
def _server(failures: int | None) -> Iterator[tuple[str, list[int]]]:
    """A server whose first ``failures`` answers are 504 (``None``: all)."""
    hits: list[int] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- the stdlib's name
            hits.append(1)
            if failures is None or len(hits) <= failures:
                self.send_response(504)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/pridem.whl", hits
    finally:
        server.shutdown()
        server.server_close()


def test_one_504_is_tried_again_and_the_file_arrives(tmp_path: Path) -> None:
    """The second try comes after the pause (``--retry-delay 2``)."""
    target = tmp_path / "pridem.whl"
    with _server(failures=1) as (url, hits):
        started = time.monotonic()
        code, said = _bash(f'fetch "{url}" "{target}"')
        took = time.monotonic() - started
    assert code == 0, said
    assert target.read_bytes() == PAYLOAD
    assert len(hits) == 2
    assert took >= 1.5, took


def test_curl_retries_on_any_error_by_its_form() -> None:
    """``--retry`` alone already tries a 504 again (curl 8.5, measured at the
    DM-80 gate): ``--retry-all-errors`` -- a refused connection, a reset -- is
    held by the form of the array, not by a server here."""
    line = re.search(r"^curl_get=\((.*)\)$", INSTALL.read_text(), re.M)
    assert line is not None
    assert line.group(1).split() == [
        "curl",
        "-fsSL",
        "--retry",
        "5",
        "--retry-all-errors",
        "--retry-delay",
        "2",
    ]


def test_504_every_time_is_six_tries_and_a_refusal_with_the_address(
    tmp_path: Path,
) -> None:
    target = tmp_path / "pridem.whl"
    with _server(failures=None) as (url, hits):
        code, said = _bash(f'fetch "{url}" "{target}"')
    assert code == 1
    assert f"install.sh: cannot download {url}" in said, said
    assert len(hits) == 6  # the first try and five more
    assert not target.exists()


STUB = """#!{python}
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
if name == "git":
    calls = sum(1 for line in open(os.environ["STUB_LOG"]) if '"git"' in line)
    dest = pathlib.Path(sys.argv[-1])
    dest.mkdir(parents=True)
    (dest / "partial").write_text("")
    if calls <= int(os.environ["STUB_FAILS"]):
        sys.exit(128)
"""


def _clone(tmp_path: Path, fails: int) -> tuple[int, list[str], list[list[str]]]:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name in ("git", "sleep"):
        stub = stubs / name
        stub.write_text(STUB.format(python=sys.executable))
        stub.chmod(0o755)
    log = tmp_path / "calls"
    script = (
        f'export STUB_LOG="{log}" STUB_FAILS={fails}\n'
        f'clone v1.2.3 https://github.com/o/pridem.git "{tmp_path}/pridem"\n'
    )
    code, said = _bash(script, path=f"{stubs}:{os.environ['PATH']}")
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    return code, said, calls


def test_a_clone_that_fails_twice_arrives_on_the_third_try(tmp_path: Path) -> None:
    code, said, calls = _clone(tmp_path, fails=2)
    assert code == 0, said
    gits = [call for call in calls if call[0] == "git"]
    assert len(gits) == 3
    assert gits[0][1:] == [
        "clone",
        "--quiet",
        "--depth",
        "1",
        "--branch",
        "v1.2.3",
        "https://github.com/o/pridem.git",
        f"{tmp_path}/pridem",
    ]
    assert [call for call in calls if call[0] == "sleep"] == [["sleep", "2"]] * 2
    assert (tmp_path / "pridem" / "partial").exists()  # the third try's


def test_five_failed_clones_are_a_refusal_with_the_repository(tmp_path: Path) -> None:
    code, said, calls = _clone(tmp_path, fails=5)
    assert code == 1
    assert (
        "install.sh: cannot clone https://github.com/o/pridem.git at v1.2.3" in said
    ), said
    assert len([call for call in calls if call[0] == "git"]) == 5
    assert (
        len([call for call in calls if call[0] == "sleep"]) == 4
    )  # not after the last
    assert not (tmp_path / "pridem").exists()  # each failed try's removed


def test_every_download_and_clone_goes_through_the_retries() -> None:
    """Outside ``fetch`` and ``clone`` the script calls neither ``curl`` nor
    ``git clone``: a new download cannot skip the retries. The pair: the two
    are called -- sops and the wheel by ``fetch``, pridem by ``clone``."""
    text = INSTALL.read_text(encoding="utf-8")
    rest = text
    for definition in (
        r"^curl_get=\(.*?\)\n",
        r"^fetch\(\) \{.*?^\}\n",
        r"^clone\(\) \{.*?^\}\n",
    ):
        rest = re.sub(definition, "", rest, count=1, flags=re.M | re.S)
    commands = [line for line in rest.splitlines() if not line.lstrip().startswith("#")]
    assert not [line for line in commands if re.search(r"\bcurl\s+-", line)]
    assert not [line for line in commands if re.search(r"\bgit\s+clone\b", line)]
    assert len([line for line in commands if line.lstrip().startswith("fetch ")]) == 2
    assert len([line for line in commands if line.lstrip().startswith("clone ")]) == 1
