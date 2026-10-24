"""Contract 2 section 4: what a verdict looks like to a person, a script, a chat.

Every renderer is a pure function of the verdict (and, for the breakage report,
of the journal lines of the run): nothing is stored, the source is one.

- ``summary_line`` -- the one line the console prints at the end;
- ``render_json`` -- the verdict object for scripts and the Panel;
- ``render_report`` -- the breakage report in markdown, sections in the order
  of the contract; the output of a failed command comes from the journal,
  matched to the step by ``(phase, stack, name)``;
- ``render_llm`` -- the same report without the green part (``ok`` steps and
  role skips; skips after a failure become one line with their count) and with
  foreign lines cut: a line to ``LINE_LIMIT`` characters, a block to
  ``TAIL_LINES`` lines, each block in a fence longer than any run of backticks
  in it, so log text cannot close the fence and talk to the reader.

The verdict is clean of secrets when it is built; journal lines are cleaned
here with the same ``Secrets``, so no renderer depends on how the journal was
written. A reason, an incomplete entry and a doctor entry are codes with
parameters; their words come from ``catalog`` (``ENGLISH`` by default), and so
does every other word and every piece of layout a renderer prints -- headings,
labels, units, the summary line: the only text here that is not the catalog's
is the verdict's data. ``--llm`` tells the skips after a failure by their codes.
"""

import json
import re
from collections.abc import Mapping, Sequence

from pydantic import BaseModel

from pridem.events import Json, LogLine, Secrets
from pridem.report.catalog import ENGLISH, Catalog, say, text
from pridem.report.codes import SKIPPED_AFTER
from pridem.report.schema import DoctorDiff, Failure, Step, Verdict
from pridem.runner import TAIL_LINES

LINE_LIMIT = 200
"""Longest foreign line ``--llm`` keeps, in characters, the cut mark included."""

_BACKTICKS = re.compile(r"`+")


def duration(seconds: float, catalog: Catalog = ENGLISH) -> str:
    """``7m12s``; ``42s`` under a minute; ``1h05m03s`` from an hour (English)."""
    total = int(seconds)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return say(catalog, "@duration.h", h=hours, m=f"{minutes:02d}", s=f"{secs:02d}")
    if minutes:
        return say(catalog, "@duration.m", m=minutes, s=f"{secs:02d}")
    return say(catalog, "@duration.s", s=secs)


def _value(value: Json) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _composition(verdict: Verdict, catalog: Catalog) -> list[str]:
    before, after = verdict.composition_before, verdict.composition_after
    keys = [*after, *(key for key in before if key not in after)]
    missing = say(catalog, "@missing")
    parts = []
    for key in keys:
        old, new = before.get(key, missing), after.get(key, missing)
        if old == new:
            parts.append(say(catalog, "@composition.same", name=key, value=new))
        else:
            parts.append(
                say(catalog, "@composition.changed", name=key, before=old, after=new)
            )
    return parts


def summary_line(verdict: Verdict, catalog: Catalog = ENGLISH) -> str:
    """``deploy 9a1c4e2 → green · 7m12s · aivis 8f0b21d→9a1c4e2 · … · passport v7``."""
    head = " ".join([verdict.verb, *(_value(v) for v in verdict.args.values())])
    spent = duration((verdict.finished - verdict.started).total_seconds(), catalog)
    return say(
        catalog,
        "@summary",
        head=head,
        result=verdict.result,
        duration=spent,
        composition=say(catalog, "@summary.sep").join(_composition(verdict, catalog)),
        passport=say(catalog, "@passport", version=verdict.passport_version),
    )


def render_json(verdict: Verdict) -> str:
    """The verdict object of contract 2 section 1."""
    return verdict.model_dump_json(indent=2)


def _cut_line(line: str) -> str:
    return line if len(line) <= LINE_LIMIT else line[: LINE_LIMIT - 1] + "…"


def _block(lines: Sequence[str], llm: bool, catalog: Catalog) -> list[str]:
    """Foreign lines in a fence no line of theirs can close."""
    shown = list(lines)
    out: list[str] = []
    if llm:
        dropped = len(shown) - TAIL_LINES
        shown = [_cut_line(line) for line in shown[-TAIL_LINES:]]
        if dropped > 0:
            out.append(say(catalog, "@block.cut", count=dropped))
    longest = max(
        (len(run) for line in shown for run in _BACKTICKS.findall(line)), default=0
    )
    fence = "`" * max(3, longest + 1)
    return [*out, fence + say(catalog, "@block.info"), *shown, fence]


def words(catalog: Catalog, item: BaseModel) -> str:
    """The words for a reason, an incomplete entry or a doctor entry."""
    params = item.model_dump()
    if isinstance(item, DoctorDiff):  # where it is, not what it says
        del params["stack"], params["name"]
    code = str(params.pop("code"))
    what = params.pop("what", None)  # never a parameter: the name is taken
    return text(catalog, code, params, None if what is None else str(what))


def _output(
    step: Step, journal: Sequence[LogLine], secrets: Secrets, catalog: Catalog
) -> list[str]:
    return [
        secrets.text(say(catalog, "@output", stream=item.stream, line=item.line))
        for item in journal
        if (item.phase, item.stack, item.name) == (step.phase, step.stack, step.name)
    ]


def _failed_steps(
    verdict: Verdict,
    journal: Sequence[LogLine] | None,
    secrets: Secrets,
    llm: bool,
    catalog: Catalog,
) -> list[str]:
    failed = [step for step in verdict.steps if step.status == "failed"]
    if not failed:
        return []
    out = [say(catalog, "@failed.heading"), ""]
    for step in failed:
        title = say(
            catalog, "@failed.title", stack=step.stack, name=step.name, order=step.order
        )
        reason = words(catalog, step.reason) if step.reason is not None else ""
        out += [title, "", reason, ""]
        if journal is None:
            out += [say(catalog, "@failed.no-journal"), ""]
            continue
        output = _output(step, journal, secrets, catalog)
        if not output:
            out += [say(catalog, "@failed.no-output"), ""]
        else:
            out += [*_block(output, llm, catalog), ""]
    return out


def _failure(failure: Failure, llm: bool, catalog: Catalog) -> list[str]:
    where = say(catalog, "@failure.where", file=failure.file, line=failure.line)
    out = [say(catalog, "@failure.title", test=failure.test), "", where, ""]
    out += [*_block(failure.message.splitlines(), llm, catalog), ""]
    if failure.traceback_project_frames:
        out += [*_block(failure.traceback_project_frames, llm, catalog), ""]
    if failure.request_ids:
        ids = say(catalog, "@list.sep").join(failure.request_ids)
        out += [say(catalog, "@failure.requests", ids=ids), ""]
    return out


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def fact_line(fact: Mapping[str, Json], catalog: Catalog = ENGLISH) -> str:
    """A ``verify`` fact on one line: ``key=value, …``."""
    return say(catalog, "@fact.sep").join(
        say(catalog, "@fact", key=key, value=_value(value))
        for key, value in fact.items()
    )


def _row(step: Step, catalog: Catalog) -> str:
    spent = (
        ""
        if step.duration_s is None
        else say(catalog, "@seconds", s=f"{step.duration_s:.1f}")
    )
    if step.reason is not None:
        said = words(catalog, step.reason)
    else:
        said = fact_line(step.verify or {}, catalog)
    cells = [step.stack, step.name, str(step.order), step.status, spent, said]
    return "| " + " | ".join(_cell(cell) for cell in cells) + " |"


def _code(step: Step) -> str:
    return "" if step.reason is None else step.reason.code


def _green(step: Step) -> bool:
    return step.status == "ok" or (step.status == "skipped" and _code(step) == "role")


def _after_failure(step: Step) -> bool:
    return step.status == "skipped" and _code(step) in SKIPPED_AFTER


def _ladder(verdict: Verdict, llm: bool, catalog: Catalog) -> list[str]:
    steps = verdict.steps
    after = 0
    if llm:
        after = sum(1 for step in steps if _after_failure(step))
        steps = [
            step for step in steps if not _green(step) and not _after_failure(step)
        ]
    out = [say(catalog, "@steps.heading"), ""]
    if steps:
        out += [
            say(catalog, "@steps.header"),
            say(catalog, "@steps.rule"),
            *(_row(step, catalog) for step in steps),
            "",
        ]
    if after:
        out += [say(catalog, "@steps.after", count=after), ""]
    return out if len(out) > 2 else []


def _closing(verdict: Verdict, catalog: Catalog) -> list[str]:
    before, after = verdict.composition_before, verdict.composition_after
    keys = [*after, *(key for key in before if key not in after)]
    missing = say(catalog, "@missing")
    out = [
        say(catalog, "@composition.heading"),
        "",
        say(catalog, "@composition.header"),
        say(catalog, "@composition.rule"),
    ]
    for key in keys:
        cells = [key, before.get(key, missing), after.get(key, missing)]
        out.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    out += ["", say(catalog, "@closing.passport", version=verdict.passport_version)]
    if verdict.junit is not None:
        junit = verdict.junit
        out.append(
            say(
                catalog,
                "@closing.junit",
                total=junit.total,
                failed=junit.failed,
                skipped=junit.skipped,
            )
        )
    out.append(say(catalog, "@closing.log", log_ref=verdict.log_ref))
    return out


def _report(
    verdict: Verdict,
    journal: Sequence[LogLine] | None,
    secrets: Secrets,
    llm: bool,
    catalog: Catalog,
) -> str:
    out = [say(catalog, "@report.title", summary=summary_line(verdict, catalog)), ""]
    out += _failed_steps(verdict, journal, secrets, llm, catalog)
    if verdict.report.failures:
        out += [say(catalog, "@failures.heading"), ""]
        for failure in verdict.report.failures:
            out += _failure(failure, llm, catalog)
    if verdict.report.incomplete:
        out += [say(catalog, "@incomplete.heading"), ""]
        out += [
            say(catalog, "@incomplete.item", what=item.what, words=words(catalog, item))
            for item in verdict.report.incomplete
        ]
        out.append("")
    if verdict.report.doctor_diff:
        out += [say(catalog, "@doctor.heading"), ""]
        out += [
            say(
                catalog,
                "@doctor.item",
                stack=item.stack,
                name=item.name,
                words=words(catalog, item),
            )
            for item in verdict.report.doctor_diff
        ]
        out.append("")
    out += _ladder(verdict, llm, catalog)
    out += _closing(verdict, catalog)
    return "\n".join(out) + "\n"


def render_report(
    verdict: Verdict,
    journal: Sequence[LogLine] | None,
    secrets: Secrets,
    catalog: Catalog = ENGLISH,
) -> str:
    """The breakage report; ``journal`` is ``None`` when the run has none left."""
    return _report(verdict, journal, secrets, llm=False, catalog=catalog)


def render_llm(
    verdict: Verdict,
    journal: Sequence[LogLine] | None,
    secrets: Secrets,
    catalog: Catalog = ENGLISH,
) -> str:
    """The breakage report for a chat: no green part, foreign lines cut."""
    return _report(verdict, journal, secrets, llm=True, catalog=catalog)
