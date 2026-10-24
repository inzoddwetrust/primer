"""Contract 2 section 4: what a verdict looks like to a person, a script, a chat.

Every renderer is a pure function of the verdict (and, for the breakage report,
of the journal lines of the run): nothing is stored, the source is one.

- ``summary_line`` -- the one line the console prints at the end;
- ``render_json`` -- the verdict object for scripts and the Panel;
- ``render_report`` -- the breakage report in markdown, sections in the order
  of the contract; the output of a failed command comes from the journal;
- ``render_llm`` -- the same report without the green part (``ok`` steps and
  role skips; skips after a failure become one line with their count) and with
  foreign lines cut: a line to ``LINE_LIMIT`` characters, a block to
  ``TAIL_LINES`` lines, each block in a fence longer than any run of backticks
  in it, so log text cannot close the fence and talk to the reader.

The verdict is clean of secrets when it is built; journal lines are cleaned
here with the same ``Secrets``, so no renderer depends on how the journal was
written.
"""

import json
import re
from collections.abc import Sequence

from pridem.events import (
    AFTER_FAILURE,
    AFTER_INTERRUPT,
    ROLE_SKIP,
    Json,
    LogLine,
    Secrets,
)
from pridem.report.schema import Failure, Step, Verdict
from pridem.runner import TAIL_LINES

LINE_LIMIT = 200
"""Longest foreign line ``--llm`` keeps, in characters, the cut mark included."""

_MISSING = "—"
_BACKTICKS = re.compile(r"`+")


def duration(seconds: float) -> str:
    """``7m12s``; ``42s`` under a minute; ``1h05m03s`` from an hour."""
    total = int(seconds)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def _value(value: Json) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _composition(verdict: Verdict) -> list[str]:
    before, after = verdict.composition_before, verdict.composition_after
    keys = [*after, *(key for key in before if key not in after)]
    parts = []
    for key in keys:
        old, new = before.get(key, _MISSING), after.get(key, _MISSING)
        parts.append(f"{key} {new}" if old == new else f"{key} {old}→{new}")
    return parts


def summary_line(verdict: Verdict) -> str:
    """``deploy 9a1c4e2 → green · 7m12s · aivis 8f0b21d→9a1c4e2 · … · passport v7``."""
    head = " ".join([verdict.verb, *(_value(v) for v in verdict.args.values())])
    spent = duration((verdict.finished - verdict.started).total_seconds())
    return " · ".join(
        [
            f"{head} → {verdict.result}",
            spent,
            *_composition(verdict),
            f"passport v{verdict.passport_version}",
        ]
    )


def render_json(verdict: Verdict) -> str:
    """The verdict object of contract 2 section 1."""
    return verdict.model_dump_json(indent=2)


def _cut_line(line: str) -> str:
    return line if len(line) <= LINE_LIMIT else line[: LINE_LIMIT - 1] + "…"


def _block(lines: Sequence[str], llm: bool) -> list[str]:
    """Foreign lines in a fence no line of theirs can close."""
    shown = list(lines)
    out: list[str] = []
    if llm:
        dropped = len(shown) - TAIL_LINES
        shown = [_cut_line(line) for line in shown[-TAIL_LINES:]]
        if dropped > 0:
            out.append(f"… {dropped} earlier lines cut")
    longest = max(
        (len(run) for line in shown for run in _BACKTICKS.findall(line)), default=0
    )
    fence = "`" * max(3, longest + 1)
    return [*out, f"{fence}text", *shown, fence]


def _output(step: Step, journal: Sequence[LogLine], secrets: Secrets) -> list[str]:
    return [
        secrets.text(f"[{item.stream}] {item.line}")
        for item in journal
        if (item.stack, item.name) == (step.stack, step.name)
    ]


def _failed_steps(
    verdict: Verdict, journal: Sequence[LogLine] | None, secrets: Secrets, llm: bool
) -> list[str]:
    failed = [step for step in verdict.steps if step.status == "failed"]
    if not failed:
        return []
    out = ["## Failed steps", ""]
    for step in failed:
        out += [
            f"### {step.stack} · {step.name} · order {step.order}",
            "",
            f"{step.reason}",
            "",
        ]
        if journal is None:
            out += ["Command output unavailable: this run has no journal left.", ""]
            continue
        output = _output(step, journal, secrets)
        if not output:
            out += ["No command output in the journal for this step.", ""]
        else:
            out += [*_block(output, llm), ""]
    return out


def _failure(failure: Failure, llm: bool) -> list[str]:
    out = [f"### {failure.test}", "", f"{failure.file}:{failure.line}", ""]
    out += [*_block(failure.message.splitlines(), llm), ""]
    if failure.traceback_project_frames:
        out += [*_block(failure.traceback_project_frames, llm), ""]
    if failure.request_ids:
        out += [f"Request ids: {', '.join(failure.request_ids)}", ""]
    return out


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def _row(step: Step) -> str:
    spent = "" if step.duration_s is None else f"{step.duration_s:.1f} s"
    if step.reason is not None:
        said = step.reason
    else:
        said = ", ".join(f"{k}={_value(v)}" for k, v in (step.verify or {}).items())
    cells = [step.stack, step.name, str(step.order), step.status, spent, said]
    return "| " + " | ".join(_cell(cell) for cell in cells) + " |"


def _green(step: Step) -> bool:
    return step.status == "ok" or (
        step.status == "skipped" and (step.reason or "").startswith(ROLE_SKIP)
    )


def _after_failure(step: Step) -> bool:
    reason = step.reason or ""
    return step.status == "skipped" and (
        reason.startswith(AFTER_FAILURE) or reason == AFTER_INTERRUPT
    )


def _ladder(verdict: Verdict, llm: bool) -> list[str]:
    steps = verdict.steps
    after = 0
    if llm:
        after = sum(1 for step in steps if _after_failure(step))
        steps = [
            step for step in steps if not _green(step) and not _after_failure(step)
        ]
    out = ["## Steps", ""]
    if steps:
        out += [
            "| stack | step | order | status | duration | fact or reason |",
            "|---|---|---|---|---|---|",
            *(_row(step) for step in steps),
            "",
        ]
    if after:
        out += [f"{after} steps skipped after the failure.", ""]
    return out if len(out) > 2 else []


def _closing(verdict: Verdict) -> list[str]:
    before, after = verdict.composition_before, verdict.composition_after
    keys = [*after, *(key for key in before if key not in after)]
    out = ["## Composition", "", "| | before | after |", "|---|---|---|"]
    for key in keys:
        cells = [key, before.get(key, _MISSING), after.get(key, _MISSING)]
        out.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    out += ["", f"Passport v{verdict.passport_version}"]
    if verdict.junit is not None:
        junit = verdict.junit
        counts = f"{junit.total} total, {junit.failed} failed, {junit.skipped} skipped"
        out.append(f"JUnit: {counts}")
    out.append(f"Log: {verdict.log_ref}")
    return out


def _report(
    verdict: Verdict, journal: Sequence[LogLine] | None, secrets: Secrets, llm: bool
) -> str:
    out = [f"# {summary_line(verdict)}", ""]
    out += _failed_steps(verdict, journal, secrets, llm)
    if verdict.report.failures:
        out += ["## Failed tests", ""]
        for failure in verdict.report.failures:
            out += _failure(failure, llm)
    if verdict.report.incomplete:
        out += ["## Incomplete", ""]
        out += [f"- {item.what} — {item.why}" for item in verdict.report.incomplete]
        out.append("")
    if verdict.report.doctor_diff:
        out += ["## Doctor diff", ""]
        out += [
            f"- {item.stack} · {item.name} — {item.what}"
            for item in verdict.report.doctor_diff
        ]
        out.append("")
    out += _ladder(verdict, llm)
    out += _closing(verdict)
    return "\n".join(out) + "\n"


def render_report(
    verdict: Verdict, journal: Sequence[LogLine] | None, secrets: Secrets
) -> str:
    """The breakage report; ``journal`` is ``None`` when the run has none left."""
    return _report(verdict, journal, secrets, llm=False)


def render_llm(
    verdict: Verdict, journal: Sequence[LogLine] | None, secrets: Secrets
) -> str:
    """The breakage report for a chat: no green part, foreign lines cut."""
    return _report(verdict, journal, secrets, llm=True)
