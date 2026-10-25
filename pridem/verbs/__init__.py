"""The machine's verbs (TZ sections 7.2, 9.1): each an argument schema and a run.

The schema and the run are shared by the CLI and, from P2, the Panel's queue;
``cli.py`` only turns a command line into a verb's arguments. An unknown verb
or argument, and a busy box, are refused before anything runs: exit 1, a
message on stderr, no verdict (contract 2 v1.9).
"""

from pridem.verbs.base import Context, Refused, Verb
from pridem.verbs.status import STATUS
from pridem.verbs.version import VERSION

VERBS: dict[str, Verb] = {verb.name: verb for verb in (VERSION, STATUS)}

__all__ = ["VERBS", "Context", "Refused", "Verb"]
