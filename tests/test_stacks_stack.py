"""Stack as an object and the composition of a box (DM-7, contract 3 v1.7)."""

import pytest
from contract_support import FIXTURES
from passport_support import EXAMPLE as PASSPORT

from pridem.stacks.lock import load_primer_lock
from pridem.stacks.passport import Package, load_passport
from pridem.stacks.schema import Product, Service, load_primer_yaml
from pridem.stacks.stack import Stack, composition, repo_name


def _example_stacks() -> list[Stack]:
    product = load_primer_yaml(FIXTURES / "product.yaml")
    service = load_primer_yaml(FIXTURES / "service.yaml")
    lock = load_primer_lock(FIXTURES / "primer.lock")
    assert isinstance(product, Product) and isinstance(service, Service)
    return [
        Stack.service(service, lock.dependencies["comms"]),
        Stack.remote_service("meet", lock.dependencies["meet"]),
        Stack.product(product, "9a1c4e2"),
    ]


def test_composition_of_the_contract_examples() -> None:
    passport = load_passport(PASSPORT)
    built = composition(
        _example_stacks(), machine_version="0.3.1", packages=passport.packages
    )
    assert built == {
        "comms": "3.0.0",
        "meet": "1.0.0",
        "aivis": "9a1c4e2",
        "pridem": "0.3.1",
        "skin": "velo-look@1.4.2",
        "texts": "velo-look@1.4.2",
    }


def test_remote_dependency_carries_the_lock_version() -> None:
    lock = load_primer_lock(FIXTURES / "primer.lock")
    meet = Stack.remote_service("meet", lock.dependencies["meet"])
    assert (meet.name, meet.kind, meet.version, meet.remote) == (
        "meet",
        "service",
        "1.0.0",
        True,
    )
    built = composition([meet], machine_version="0.3.1", packages={})
    assert built == {"meet": "1.0.0", "pridem": "0.3.1"}


@pytest.mark.parametrize(
    ("repo", "name"),
    [
        ("git@github.com:partner-x/velo-look.git", "velo-look"),
        ("https://github.com/partner-x/velo-look.git", "velo-look"),
        ("https://github.com/partner-x/velo-look", "velo-look"),
        ("git@github.com:velo-look.git", "velo-look"),
        ("ssh://git@host:2222/agency/team/velo-look.git/", "velo-look"),
    ],
)
def test_package_repo_is_the_base_name(repo: str, name: str) -> None:
    assert repo_name(repo) == name


def test_package_account_never_reaches_the_composition() -> None:
    package = Package.model_validate(
        {"repo": "git@github.com:partner-x/velo-look.git", "version": "1.4.2"}
    )
    built = composition([], machine_version="0.3.1", packages={"skin": package})
    assert built == {"pridem": "0.3.1", "skin": "velo-look@1.4.2"}
    assert not any("partner-x" in value or ".git" in value for value in built.values())


def test_no_stacks_is_the_machine_alone() -> None:
    assert composition([], machine_version="0.3.1", packages={}) == {"pridem": "0.3.1"}
