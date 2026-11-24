"""What the kernel says of the host's memory: ``/proc/meminfo`` under a root.

One reader for ``pridem state`` (DM-136) and the steps that judge memory
(``memory``, DM-132): two copies of a parser drift apart. A leaf: it imports
nothing of the machine.
"""

from pathlib import Path

GIB = 2**30


def meminfo(root: Path) -> dict[str, int] | None:
    """``/proc/meminfo`` in bytes by its keys; ``None`` -- not readable."""
    try:
        text = (root / "proc" / "meminfo").read_text(encoding="utf-8")
    except OSError:
        return None
    found: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        words = rest.split()
        if words and words[0].isdigit():
            unit = 1024 if words[1:2] == ["kB"] else 1
            found[key.strip()] = int(words[0]) * unit
    return found
