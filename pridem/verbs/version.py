"""``pridem version``: the installed version; no lock, no verdict, no root."""

from pridem import __version__
from pridem.contract import Strict
from pridem.verbs.base import Context, NoArgs, Verb


def _run(args: Strict, ctx: Context) -> int:
    ctx.out.write(f"pridem {__version__}\n")
    return 0


VERSION = Verb("version", NoArgs, _run, verdict=False)
