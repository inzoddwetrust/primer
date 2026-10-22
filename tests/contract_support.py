"""Helpers for contract-3 tests: the contract's own examples as mutable data."""

from pathlib import Path

import yaml

from pridem.stacks.loader import ContractError
from pridem.stacks.lock import check_lock, load_primer_lock
from pridem.stacks.schema import Product, load_primer_yaml

FIXTURES = Path(__file__).parent / "fixtures" / "primer"

Data = dict[str, object]
Found = list[tuple[str, str]]


def example(name: str) -> Data:
    """A fresh dict of ``product.yaml``, ``service.yaml`` or ``primer.lock``."""
    data = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def node(data: object, *keys: str | int) -> Data:
    """The mapping at ``keys`` inside ``data``, for editing in place."""
    current = data
    for key in keys:
        if isinstance(key, int):
            assert isinstance(current, list)
            current = current[key]
        else:
            assert isinstance(current, dict)
            current = current[key]
    assert isinstance(current, dict)
    return current


def write(directory: Path, name: str, data: Data) -> Path:
    file = directory / name
    file.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    return file


def yaml_problems(directory: Path, data: Data) -> Found:
    """(path, code) of every problem of ``data`` as primer.yaml; [] if it loads."""
    try:
        load_primer_yaml(write(directory, "primer.yaml", data))
    except ContractError as error:
        return [(p.path, p.code) for p in error.problems]
    return []


def yaml_messages(directory: Path, data: Data) -> list[str]:
    try:
        load_primer_yaml(write(directory, "primer.yaml", data))
    except ContractError as error:
        return [p.message for p in error.problems]
    return []


def lock_problems(directory: Path, primer: Data, lock: Data) -> Found:
    """Problems of ``lock`` alone, or else of the lock against ``primer``."""
    try:
        loaded = load_primer_lock(write(directory, "primer.lock", lock))
    except ContractError as error:
        return [(p.path, p.code) for p in error.problems]
    product = load_primer_yaml(write(directory, "primer.yaml", primer))
    assert isinstance(product, Product)
    return [(p.path, p.code) for p in check_lock(product, loaded)]
