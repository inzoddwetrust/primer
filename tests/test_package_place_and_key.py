"""A package's repository and its key (DM-127).

A package of the passport from a repository over ssh has its key, as a
product's or a service's, in a stack of its slot (contract 1 section 9;
review 0004, finding 4). The check of a package's place in its build context
was taken off (DM-127 FIX): the machine does not know what a product's build
reads -- a place's directory may be the repository's or made by the machine;
tier 3 holds that the frontend serves the skin.
"""

from pathlib import Path

from history_support import deploy_verbs_box

from pridem.steps.keys import DeployKey


def test_a_package_from_its_repository_has_its_key(tmp_path: Path) -> None:
    """K1, K2: the passport's packages from ``git@github.com:partner-x/...``
    -- a stack of each slot before ``pridem-sources``, its key of the
    package's address, the product's and the other packages' addresses its
    others (no alias clash); the pair: the product's key, as before."""
    sources = deploy_verbs_box(tmp_path, "update", "test")
    built = sources.build()  # type: ignore[union-attr]
    assert built is not None
    names = [part.name for part in built]
    assert names == ["pridem-package-skin", "pridem-package-texts", "pridem-sources"]
    keys = {part.name: part.steps[0] for part in built[:2]}
    for key in keys.values():
        assert isinstance(key, DeployKey)
        assert key.repo.address == "git@github.com:partner-x/velo-look.git"
        assert "git@github.com:aivis-one/aivis.git" in key.others
    product_key = built[2].steps[0]
    assert isinstance(product_key, DeployKey)
    assert product_key.repo.address == "git@github.com:aivis-one/aivis.git"
