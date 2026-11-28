"""The tag of a release of the machine and the commit it must name (DM-187:
REVIEW-0006 S8, D7), for ``release.yml``. What the remote says of
``refs/tags/<tag>`` -- read by ``git ls-remote``, an annotated tag by the
commit it peels to:

- ``new`` -- no such tag;
- ``same`` -- the tag names the commit;
- ``moved`` -- the tag names another commit: ``tag-moved``.

``python tools/release_tag.py <remote> <tag> <commit>`` prints the state and
exits 0 for ``new`` and ``same``, 1 for ``moved`` with ``tag-moved: <tag> is
<found>, the release is <commit>``. Its callers in ``release.yml``: the guard
of a pushed tag (the release's pinned ``COMMIT`` against the tag), and the
button after a failed ``gh release create`` (it deletes only a tag that is
still its own). A tag is made by the button alone (DM-125), by ``POST
git/refs`` -- refused when the ref is there, so no check and make race.

Commands go through ``pridem.runner.SubprocessRunner`` (par0 10: no
``subprocess`` but in ``runner.py``).
"""

import sys
from typing import Literal

from pridem.runner import Stream, SubprocessRunner

State = Literal["new", "same", "moved"]


def tag_commit(remote: str, tag: str) -> str | None:
    """The commit ``refs/tags/<tag>`` of ``remote`` names -- peeled when the tag
    is annotated; ``None`` -- no such tag."""
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            lines.append(line)

    ref = f"refs/tags/{tag}"
    SubprocessRunner().run(
        ["git", "ls-remote", "--tags", remote, ref, f"{ref}^{{}}"],
        timeout=120,
        on_line=keep,
    )
    found: dict[str, str] = {}
    for line in lines:
        sha, sep, name = line.partition("\t")
        if sep:
            found[name] = sha
    return found.get(f"{ref}^{{}}") or found.get(ref)


def state(remote: str, tag: str, commit: str) -> State:
    """``new``, ``same`` or ``moved`` -- the tag against the release's commit."""
    found = tag_commit(remote, tag)
    if found is None:
        return "new"
    return "same" if found == commit else "moved"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: release_tag.py <remote> <tag> <commit>", file=sys.stderr)
        return 2
    remote, tag, commit = argv
    found = state(remote, tag, commit)
    print(found)
    if found == "moved":
        print(
            f"tag-moved: {tag} is {tag_commit(remote, tag)}, the release is {commit}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
