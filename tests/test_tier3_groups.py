"""The groups of tier 3 (DM-73): the table and the selection of a job.

``tier3/groups.py`` is the one table; ``tier3/conftest.py`` keeps the tests of
the job's group and refuses -- never skips -- a test in no group or in two.
The hook (``groups.keep_group``, what the conftest gives pytest) is called
here as pytest calls it, on stand-in items.
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

TIER3 = Path(__file__).resolve().parent.parent / "tier3"


if str(TIER3) not in sys.path:  # tier 3 is no package; its conftest imports so
    sys.path.insert(0, str(TIER3))

import groups  # noqa: E402


@dataclass
class Item:
    name: str


@dataclass
class Hook:
    deselected: list[Item] = field(default_factory=list)

    def pytest_deselected(self, items: list[Item]) -> None:
        self.deselected += items


@dataclass
class Config:
    group: str
    hook: Hook = field(default_factory=Hook)

    def getoption(self, name: str) -> str:
        assert name == "--tier3-group"
        return self.group


def keep(config: Config, items: list[Item]) -> None:
    """``groups.keep_group`` on the stand-ins, as pytest calls it."""
    groups.keep_group(cast(pytest.Config, config), cast(list[pytest.Item], items))


def _items(*names: str) -> list[Item]:
    return [Item(name) for name in names]


def test_a_job_keeps_its_group_in_the_order_of_the_files() -> None:
    """G5: the others' tests are deselected, not run; parameters keep their
    function's group."""
    items = _items(
        "test_probe_DM_16_status_on_a_fresh_box_is_green",
        "test_tier3_the_whole_install_of_the_blank",
        "test_tier3_certbot_tag_has_the_pinned_digest[one]",
        "test_tier3_certbot_tag_has_the_pinned_digest[two]",
    )
    config = Config("a")
    keep(config, items)
    assert [i.name for i in items] == [
        "test_probe_DM_16_status_on_a_fresh_box_is_green",
        "test_tier3_certbot_tag_has_the_pinned_digest[one]",
        "test_tier3_certbot_tag_has_the_pinned_digest[two]",
    ]
    assert [i.name for i in config.hook.deselected] == [
        "test_tier3_the_whole_install_of_the_blank"
    ]


@pytest.mark.parametrize(
    "rows",
    [(), (("test_x", "a"), ("test_x", "b"))],
    ids=["no-group", "two-groups"],
)
def test_a_test_in_no_group_or_in_two_is_a_usage_error(
    rows: tuple[tuple[str, str], ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    """G4: never a skip -- the collection stops with the test's name."""
    monkeypatch.setattr(groups, "GROUPS", (*groups.GROUPS, *rows))
    items = _items("test_probe_DM_16_status_on_a_fresh_box_is_green", "test_x")
    expected = "in 0 groups" if not rows else "in 2 groups"
    with pytest.raises(pytest.UsageError, match=f"test_x: {expected}"):
        keep(Config("a"), items)
    assert len(items) == 2  # nothing dropped quietly


def test_a_group_with_no_test_is_a_usage_error() -> None:
    with pytest.raises(pytest.UsageError, match="has no test"):
        keep(Config("z"), _items())


def test_the_table_is_whole_and_its_selftest_catches_each_defect() -> None:
    """The table against the files and the matrix of tier3.yml, and the five
    planted defects -- the step of CI, here too.

    Changed by DM-85: group ``c`` is cut in two, ``f`` with an install of its
    own -- six groups; the groups the fixture installs the blank for are named
    by equality, not as a subset of the matrix: ``f`` left out of
    ``NEEDS_BOX`` is red here, not first on tier 3."""
    assert groups.check() == 0
    assert groups.selftest() == 0
    assert (
        set(groups.matrix())
        == {g for _, g in groups.GROUPS}
        == {"a", "b", "c", "d", "e", "f"}
    )
    assert groups.NEEDS_BOX == {"c", "e", "f"}
