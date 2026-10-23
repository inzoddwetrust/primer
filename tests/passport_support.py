"""Helpers for contract-1 tests: the passport example as mutable data."""

import traceback
from pathlib import Path

import yaml

from pridem.stacks.loader import ContractError
from pridem.stacks.passport import load_passport

EXAMPLE = Path(__file__).parent / "fixtures" / "passport" / "passport.yaml"

Data = dict[str, object]
Found = list[tuple[str, str]]


def passport_example() -> Data:
    """A fresh dict of the example of contract 1 section 1."""
    data = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def section(data: Data, *keys: str) -> Data:
    """The mapping at ``keys`` inside ``data``, for editing in place."""
    current: object = data
    for key in keys:
        assert isinstance(current, dict)
        current = current[key]
    assert isinstance(current, dict)
    return current


def write_passport(directory: Path, data: Data) -> Path:
    file = directory / "passport.yaml"
    file.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    return file


def rejection(file: Path) -> ContractError | None:
    try:
        load_passport(file)
    except ContractError as error:
        return error
    return None


def passport_problems(directory: Path, data: Data) -> Found:
    """(path, code) of every problem of ``data`` as a passport; [] if it loads."""
    error = rejection(write_passport(directory, data))
    return [] if error is None else [(p.path, p.code) for p in error.problems]


def passport_messages(directory: Path, data: Data) -> list[str]:
    error = rejection(write_passport(directory, data))
    return [] if error is None else [p.message for p in error.problems]


def everything_printed(error: ContractError) -> str:
    """All a person or a log could see of a rejection: text and traceback."""
    return str(error) + "".join(traceback.format_exception(error))
