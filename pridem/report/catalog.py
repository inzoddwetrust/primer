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
    "run/unbuildable": "the verdict of this run could not be built ({type}); "
    "its journal holds the rest",
    "journal/write-failed": (
        "the journal stopped being written; the plan reached finally"
    ),
    "journal/quarantined": "journal {run_id} is in quarantine",
    "journal/cut": "the run's output past {limit} bytes is not in its journal",
    "state/quarantined": "state.json was damaged and is in quarantine",
    "restore/needed": "past the point of no return: restore from backup is needed",
    "restore/empty": "past the point of no return on databases that were empty "
    "before this run: there is nothing to restore — fix the cause and run it again",
    "@at": "{phase} {stack} · {name}",
    "@unknown": "{code} ({params}) — no words in this catalog",
    "@null:ended_at": "the start",
    "@null:errno": "no errno",
    # --- the renderers' words and layout ---
    "@summary": "{head} → {result} · {duration} · {composition} · {passport}",
    "@summary.no-passport": "{head} → {result} · {duration} · {composition}",
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
    "@rollback.passport-ref": "the passport still names {ref}: the next update "
    "brings it back — change the passport",
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
    "@console.step": "{mark} {label}",
    "@console.of": "{stack} · {title}",
    "@console.duration": " · {seconds}",
    "@console.fact": " · {fact}",
    "@console.reason": " — {reason}",
    "@console.cause": "           {cause}",
    "@console.idle": " · nothing to do",
    "@console.begins": "→ {label}…",
    "@console.live": "{label} · {spent}",
    "@doctor.line": "- {title} — {words}",
    "@header": "pridem {version} — {verb}{where}",
    "@header.on": " on {server}",
    "@state.stack": "{stack} · {release}",
    "@state.stacks.empty": "no stacks on this box",
    "@state.stacks.none": "stacks: {why}",
    "@state.entry": "  {entry} — {services}",
    "@state.entry.none": "  entries: {why}",
    "@state.entry.empty": "no services",
    "@state.service": "{service} {state}",
    "@state.disk": "disk {path} — {shown}",
    "@state.memory": "memory — {shown}",
    "@state.swap": "swap — {shown}",
    "@state.swap.none": "none",
    "@state.free": "{free} free of {total}",
    "@state.images": "images — {shown}",
    "@state.images.size": "{count}, {size}, {reclaimable} reclaimable",
    "@state.ssl": "ssl {mode} — ends {expires}, renews from {renews}",
    "@state.ssl.none": "ssl — {why}",
    "@state.ssl.covered": "  {domain} — ends {expires}",
    "@state.ssl.uncovered": "  {domain} — not in the certificate",
    "@state.lock": "the lock is open by {by}",
    "@state.journals": "journals without a verdict: {runs}",
    "@state.unmeasured": "not measured ({why})",
    "@end.green": "{head}: done in {duration}.",
    "@end.incomplete": "{head}: done in {duration}, something is left:",
    "@end.red": "{head}: failed in {duration} at {title} — {reason}.",
    "@end.clean": "Nothing to fix: the box is as its passport says.",
    "@end.doctor": "{head}: done in {duration}, {count} step(s) would act.",
    "@end.stopped": "{head}: stopped in {duration}.",
    "@end.left": "  - {words}",
    "@end.site": "Site: https://{domain}",
    "@end.versions": "Versions: {versions}",
    "@end.log": "Full log: /opt/pridem/{log_ref}",
    "@end.next": "Next: pridem report {run_id}",
    "@key.title": "Deploy key — add this key to {repo}",
    "@key.go": "Go to: {page}",
    "@key.add": "Click 'Add deploy key', paste the key above.",
    "@key.read": "READ-ONLY is enough: do NOT tick 'Allow write access'.",
    "@key.write": "IMPORTANT: tick 'Allow write access' — {why}.",
    "@key.already": "Already added? The box goes on by itself as soon as the key "
    "works.",
    "@key.again": "GitHub has not taken the key yet: it worked, then {repo} "
    "refused it. The box waits again.",
    "@key.waits": "Waiting for access to {repo}, up to {wait}…",
    "@key.waiting": "Waiting for access to {subject} · {spent} of {wait}",
    "@recipient.title": "Passport key of this box — add it to the ops repository",
    "@recipient.add": "Add it as a recipient of {path} in the ops repository and "
    "encrypt the passport again (sops with age).",
    "@recipient.any": "this box's passport, passports/<server name>.yaml,",
    "@recipient.then": "The box reads its passport as soon as it is encrypted for "
    "this key.",
    "@recipient.waits": "Waiting for {path} to be encrypted for this box, up to "
    "{wait}…",
    "@recipient.waiting": "Waiting for {subject} to be encrypted for this box · "
    "{spent} of {wait}",
    "@mark.ok": "✓",
    "@mark.failed": "✗",
    "@mark.skipped": "–",
    "@empty": "none",
}


def _present(catalog: Catalog, name: str, value: Value) -> str:
    if value is None:
        return catalog[f"@null:{name}"]
    if isinstance(value, list):  # an empty one is a word: no text ends on a
        # dangling preposition ("wait for ", DM-105)
        return shlex.join(str(item) for item in value) or catalog["@empty"]
    if isinstance(value, dict):
        return catalog["@at"].format(**{k: str(v) for k, v in value.items()})
    return str(value)


def text(
    catalog: Catalog, code: str, params: Mapping[str, Value], what: str | None = None
) -> str:
    """The words for ``code`` with ``params``. A code the catalog has no words
    for -- one of a step since removed, in an old verdict of ``history/`` --
    is said as it is, by the catalog's ``@unknown`` (DM-77; a new verdict with
    such a code is refused when it is built, contract 2 rule 6)."""
    key = catalog_key(code, what)
    if key not in catalog:
        shown = ", ".join(f"{name}={value}" for name, value in params.items())
        return catalog["@unknown"].format(code=key, params=shown)
    template = catalog[key]
    return template.format(
        **{name: _present(catalog, name, value) for name, value in params.items()}
    )


NOT_A_CAUSE: tuple[str, ...] = (
    "fatal: Could not read from remote repository.",
    "Please make sure you have the correct access rights",
    "and the repository exists.",
)
"""Lines a command prints after its failure that never say why: git's set
phrases after an ssh refusal (git 2.43; DM-111). The console shows the last
line of a failed command that is none of these and starts with none of
``NOT_A_CAUSE_STARTS`` -- ``Permission denied (publickey)``, not ``and the
repository exists.``"""
NOT_A_CAUSE_STARTS: tuple[str, ...] = ("hint:",)
CAUSE_LINES = 3
"""How many of the last lines of a failed command the console shows, each on
a row of its own under the step's line (DM-124: the reason may be a line
above the last)."""


def is_a_cause(line: str) -> bool:
    """``line`` (stripped) can say why a command failed."""
    return line not in NOT_A_CAUSE and not line.startswith(NOT_A_CAUSE_STARTS)


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
