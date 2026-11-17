"""``install.sh`` on the screen and in its log (DM-112).

The script runs for real under ``PRIDEM_ROOT`` with the commands it calls
for the network and the host -- ``apt-get``, ``curl``, ``git``, ``python3``,
``uname``, ``id``, ``sleep``, ``sha256sum`` -- stood in for by scripts in a
temporary directory first on the ``PATH``: they print what the real ones
print and leave what they would leave. They are this test's, never files of
the repository (the fence reads ``git ls-files '*.sh'``). The screen gets the
script's own lines; the rest goes to ``var/log/pridem-install.log``; a
refusal -- by ``fail`` after the last try of ``clone``, or by a command that
failed outside a condition (the ``ERR`` trap) -- says why, the log's last
lines and its path.
"""

import hashlib
from pathlib import Path

from pridem.runner import Stream, SubprocessRunner

REPO = Path(__file__).resolve().parents[1]
TAG, VERSION = "v1.2.3", "1.2.3"
COMMIT = "c" * 40

STUBS = {
    "uname": "echo x86_64\n",
    "id": "echo 0\n",
    "sleep": "exit 0\n",
    "apt-get": (
        'echo "Reading package lists... Done"\necho "W: apt says something" >&2\n'
    ),
    "curl": (
        'out=""; url=""\n'
        "while [ $# -gt 0 ]; do\n"
        "  case $1 in -o) out=$2; shift 2;; *) url=$1; shift;; esac\n"
        "done\n"
        'echo "  % Total    % Received" >&2\n'
        "case $url in\n"
        '  file://*) cp "${url#file://}" "$out";;\n'
        '  *) echo sops > "$out";;\n'
        "esac\n"
    ),
    "sha256sum": (
        "while read -r sum file; do\n"
        '  case $file in *"${FAIL_SHA:-@none@}"*)\n'
        '    echo "$file: FAILED"; exit 1;;\n'
        "  esac\n"
        '  echo "$file: OK"\n'
        "done\n"
    ),
    "git": (
        'if [ "$1" = clone ]; then\n'
        '  if [ -n "${GIT_FAILS:-}" ]; then\n'
        '    echo "fatal: unable to access" >&2; exit 128\n'
        "  fi\n"
        "  for dir; do :; done\n"
        '  mkdir -p "$dir/wheels"; : > "$dir/requirements.lock"\n'
        "  echo \"Note: switching to 'deadbeef'.\" >&2\n"
        "  echo \"You are in 'detached HEAD' state.\" >&2\n"
        "  exit 0\n"
        "fi\n"
        f"echo {COMMIT}\n"
    ),
    "python3": (
        'dir=$3; mkdir -p "$dir/bin"\n'
        'cat > "$dir/bin/pip" <<EOF\n'
        "#!/bin/sh\n"
        'echo "Collecting pyyaml"\n'
        'echo "Successfully installed"\n'
        "EOF\n"
        'cat > "$dir/bin/pridem" <<EOF\n'
        "#!/bin/sh\n"
        f'echo "pridem {VERSION}"\n'
        "EOF\n"
        'chmod 755 "$dir/bin/pip" "$dir/bin/pridem"\n'
    ),
}


def _install(tmp: Path, **env: str) -> tuple[int, list[str], list[str], Path]:
    """``install.sh`` with its pins, under ``PRIDEM_ROOT``: exit, screen, log."""
    root = tmp / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    (root / "usr" / "local" / "bin").mkdir(parents=True)
    wheel = tmp / f"pridem-{VERSION}-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    stubs = tmp / "stubs"
    stubs.mkdir()
    for name, body in STUBS.items():
        (stubs / name).write_text("#!/bin/sh\n" + body)
        (stubs / name).chmod(0o755)
    script = (REPO / "install.sh").read_text(encoding="utf-8")
    for pin, value in {
        "@PRIDEM_TAG@": TAG,
        "@PRIDEM_COMMIT@": COMMIT,
        "@PRIDEM_WHEEL_SHA256@": hashlib.sha256(b"wheel").hexdigest(),
        "@PRIDEM_REPO@": f"file://{tmp}/repo",
        "@PRIDEM_WHEEL_URL@": f"file://{wheel}",
    }.items():
        script = script.replace(pin, value)
    (tmp / "install.sh").write_text(script)
    seen: dict[Stream, list[str]] = {Stream.STDOUT: [], Stream.STDERR: []}
    result = SubprocessRunner().run(
        ["bash", str(tmp / "install.sh")],
        timeout=60,
        expect=(0, 1),
        env={"PATH": f"{stubs}:/usr/bin:/bin", "PRIDEM_ROOT": str(root), **env},
        on_line=lambda s, line, cut: seen[s].append(line),
    )
    log = root / "var" / "log" / "pridem-install.log"
    return result.code, seen[Stream.STDOUT], seen[Stream.STDERR], log


def test_a_green_install_shows_its_own_lines_and_logs_the_rest(tmp_path: Path) -> None:
    """The screen: 1/5 ... 5/5, nothing of apt, git, curl or pip; the log
    (0600) has their lines and the script's own."""
    code, screen, errors, log = _install(tmp_path)
    assert code == 0, errors
    assert [line.split(" ", 1)[0] for line in screen] == [
        "1/5",
        "2/5",
        "3/5",
        "4/5",
        "5/5",
    ]
    assert errors == []
    written = log.read_text().splitlines()
    assert oct(log.stat().st_mode & 0o777) == oct(0o600)
    assert "Reading package lists... Done" in written
    assert any("detached HEAD" in line for line in written)
    assert "Successfully installed" in written
    assert [
        line for line in written if line[:3] in {"1/5", "2/5", "3/5", "4/5", "5/5"}
    ] == screen


def test_a_clone_that_fails_every_try_shows_why_the_tail_and_the_log(
    tmp_path: Path,
) -> None:
    """``clone`` after its fifth try: the reason, the log's last lines -- the
    tries among them -- and the log's path, on the screen; the steps before
    it as they were."""
    code, screen, errors, log = _install(tmp_path, GIT_FAILS="1")
    assert code == 1
    assert [line.split(" ", 1)[0] for line in screen] == ["1/5", "2/5"]
    assert errors[0] == f"install.sh: cannot clone file://{tmp_path}/repo.git at {TAG}"
    assert errors[1] == f"--- the last lines of {log} ---"
    assert any("failed (try 5 of 5)" in line for line in errors)
    assert errors[-1] == f"Full log: {log}"


def test_a_command_that_fails_outside_a_condition_is_the_same_refusal(
    tmp_path: Path,
) -> None:
    """The wheel's checksum fails in a pipeline -- no ``fail`` of the script's,
    the ``ERR`` trap: the same reason line, tail and path."""
    code, screen, errors, log = _install(tmp_path, FAIL_SHA="pridem-")
    assert code == 1
    assert [line.split(" ", 1)[0] for line in screen] == ["1/5", "2/5", "3/5"]
    assert errors[0].startswith("install.sh: a command failed (exit 1, line ")
    assert any("FAILED" in line for line in errors)
    assert errors[-1] == f"Full log: {log}"
