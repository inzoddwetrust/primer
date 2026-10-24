"""Texts of verdict codes: the verdict stores codes and parameters, a catalog
turns them into words (contract 2 v1.6 section 4).

A catalog maps a key to a ``str.format`` template with named parameters: a
reason code, ``what/code`` of a machine incomplete entry, or a step code
``<step>:<code>``. Parameters are presented before formatting: a list of
strings (``argv``) is joined as a shell would read it, ``ended_at`` through the
``@at`` template, and a ``null`` parameter by its ``@null:<name>`` word, so a
template never branches. Keys starting with ``@`` are the renderers' own
words and layout -- headings, labels, the summary line, units, the console's
marks -- filled by ``say``; no renderer writes a word of its own. ``ENGLISH``
is the default catalog; another language is another mapping with the same
keys, and the data of a verdict does not change with it. Steps bring the
texts of their own codes (``with_steps``).
This module imports only the standard library and ``report.codes``.
"""

import shlex
from collections.abc import Iterable, Mapping

from pridem.report.codes import catalog_key

type Value = None | bool | int | float | str | list[Value] | dict[str, Value]
type Catalog = Mapping[str, str]

ENGLISH: Catalog = {
    "role": "role {role}",
    "after-failure": "after the failure of {phase} {stack} · {name}",
    "after-interrupt": "after the interrupt",
    "interrupted": "interrupted",
    "no-fact": "verify returned no fact",
    "command-failed": "command failed: {argv} — exit code {exit_code}",
    "command-timed-out": "command timed out after {timeout_s} s: {argv}",
    "command-not-started": "command not started: {argv} — {errno}",
    "exception": "unexpected {type}; its text is in the journal",
    "run/no-verdict": "no verdict; the journal ends at {ended_at}",
    "run/journal-damaged": "no verdict; the journal is damaged at line {line}",
    "journal/write-failed": (
        "the journal stopped being written; the plan reached finally"
    ),
    "journal/quarantined": "journal {run_id} is in quarantine",
    "state/quarantined": "state.json was damaged and is in quarantine",
    "restore/needed": "past the point of no return: restore from backup is needed",
    "@at": "{phase} {stack} · {name}",
    "@null:ended_at": "the start",
    "@null:errno": "no errno",
    # --- the renderers' words and layout ---
    "@summary": "{head} → {result} · {duration} · {composition} · {passport}",
    "@summary.sep": " · ",
    "@passport": "passport v{version}",
    "@composition.same": "{name} {value}",
    "@composition.changed": "{name} {before}→{after}",
    "@missing": "—",
    "@duration.h": "{h}h{m}m{s}s",
    "@duration.m": "{m}m{s}s",
    "@duration.s": "{s}s",
    "@seconds": "{s} s",
    "@fact": "{key}={value}",
    "@fact.sep": ", ",
    "@output": "[{stream}] {line}",
    "@block.cut": "… {count} earlier lines cut",
    "@block.info": "text",
    "@report.title": "# {summary}",
    "@failed.heading": "## Failed steps",
    "@failed.title": "### {stack} · {name} · order {order}",
    "@failed.no-journal": "Command output unavailable: this run has no journal left.",
    "@failed.no-output": "No command output in the journal for this step.",
    "@failures.heading": "## Failed tests",
    "@failure.title": "### {test}",
    "@failure.where": "{file}:{line}",
    "@failure.requests": "Request ids: {ids}",
    "@list.sep": ", ",
    "@incomplete.heading": "## Incomplete",
    "@incomplete.item": "- {what} — {words}",
    "@doctor.heading": "## Doctor diff",
    "@doctor.item": "- {stack} · {name} — {words}",
    "@steps.heading": "## Steps",
    "@steps.header": "| stack | step | order | status | duration | fact or reason |",
    "@steps.rule": "|---|---|---|---|---|---|",
    "@steps.after": "{count} steps skipped after the failure.",
    "@composition.heading": "## Composition",
    "@composition.header": "| | before | after |",
    "@composition.rule": "|---|---|---|",
    "@closing.passport": "Passport v{version}",
    "@closing.junit": "JUnit: {total} total, {failed} failed, {skipped} skipped",
    "@closing.log": "Log: {log_ref}",
    "@console.step": "{mark} {stack} · {name}",
    "@console.duration": " · {seconds}",
    "@console.fact": " · {fact}",
    "@console.reason": " — {reason}",
    "@mark.ok": "✓",
    "@mark.failed": "✗",
    "@mark.skipped": "–",
}


def _present(catalog: Catalog, name: str, value: Value) -> str:
    if value is None:
        return catalog[f"@null:{name}"]
    if isinstance(value, list):
        return shlex.join(str(item) for item in value)
    if isinstance(value, dict):
        return catalog["@at"].format(**{k: str(v) for k, v in value.items()})
    return str(value)


def text(
    catalog: Catalog, code: str, params: Mapping[str, Value], what: str | None = None
) -> str:
    """The words for ``code`` with ``params``; a missing key is a ``KeyError``."""
    template = catalog[catalog_key(code, what)]
    return template.format(
        **{name: _present(catalog, name, value) for name, value in params.items()}
    )


def say(catalog: Catalog, key: str, /, **values: object) -> str:
    """A renderer's own words: the template of ``key`` with ``values`` as given."""
    return catalog[key].format(**values)


def with_steps(
    catalog: Catalog, steps: Iterable[tuple[str, Mapping[str, str]]]
) -> dict[str, str]:
    """``catalog`` plus the codes each named step declares, as ``<step>:<code>``."""
    merged = dict(catalog)
    for name, codes in steps:
        for code, template in codes.items():
            merged[f"{name}:{code}"] = template
    return merged


def missing(catalog: Catalog, keys: Iterable[str]) -> list[str]:
    """The keys without a text in ``catalog``, sorted."""
    return sorted({key for key in keys if key not in catalog})
