"""``pridem report <run_id> [--json|--llm]``: a run's breakage report, from its
verdict in ``history/`` and its journal, rendered when asked and never stored
(contract 2 section 5).

Read-only: no lock -- the report of a run still going is read beside it -- and
no verdict of its own. ``--json`` prints the stored verdict, ``--llm`` the
report for a chat, neither -- the markdown report. The words of the steps'
codes are the machine's: every step class of ``pridem.steps`` gives its codes,
as the plan that ran gave them. A run with no verdict in ``history/`` (an
unknown id, or one still running) is refused; a journal that was evicted is
named as gone by the report itself.
"""

from collections.abc import Iterator

from pridem.contract import Strict
from pridem.events import LogLine, Secrets
from pridem.report.catalog import ENGLISH, Catalog, with_steps
from pridem.report.render import render_json, render_llm, render_report
from pridem.state import Box, VerdictDamaged
from pridem.steps.base import Step
from pridem.verbs import plans  # noqa: F401 -- every step class of a plan, loaded
from pridem.verbs.base import Context, Refused, Verb


class ReportArgs(Strict):
    run_id: str
    llm: bool = False


def _classes(base: type[object]) -> Iterator[type[object]]:
    for found in base.__subclasses__():
        yield found
        yield from _classes(found)


def machine_catalog() -> Catalog:
    """The machine's texts and every step's codes."""
    steps: list[tuple[str, dict[str, str]]] = []
    for found in _classes(Step):
        name, codes = getattr(found, "name", None), getattr(found, "codes", None)
        if isinstance(name, str) and isinstance(codes, dict):
            steps.append((name, {str(k): str(v) for k, v in codes.items()}))
    return with_steps(ENGLISH, steps)


def _run(args: Strict, ctx: Context) -> int:
    if not isinstance(args, ReportArgs):
        raise TypeError("report takes ReportArgs")
    box = Box(ctx.root)
    if args.run_id not in box.history_ids():
        raise Refused(f"no verdict of {args.run_id} in history")
    try:
        verdict = box.read_verdict(args.run_id)
    except VerdictDamaged as damaged:
        raise Refused(f"the verdict is damaged: {damaged}") from None
    if ctx.json:
        ctx.out.write(render_json(verdict) + "\n")
        return 0
    journal = box.read_journal(args.run_id)
    lines = (
        None
        if journal is None
        else [event for event in journal.events if isinstance(event, LogLine)]
    )
    render = render_llm if args.llm else render_report
    ctx.out.write(render(verdict, lines, Secrets(()), machine_catalog()) + "\n")
    return 0


REPORT = Verb(
    "report",
    ReportArgs,
    _run,
    positionals=("run_id",),
    verdict=False,
    options={"--llm": ("llm", "flag")},
    prints_json=True,
)
