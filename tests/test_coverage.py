"""Every action must have a test that exercises it (marked @pytest.mark.op('name'))."""

import re
from pathlib import Path

from crowdstrike_guardian.operations import operations

TESTS = Path(__file__).resolve().parent
# Quote-agnostic: ruff format normalizes string quotes, and a quote-specific
# pattern would silently stop matching every mark after a reformat.
MARK = re.compile(r"pytest\.mark\.op\(['\"]([a-z_]+)['\"]\)")


def _marked():
    names = set()
    for path in TESTS.glob("test_*.py"):
        if path.name != Path(__file__).name:
            names.update(MARK.findall(path.read_text()))
    return names


def test_every_operation_has_a_test():
    missing = set(operations) - _marked()
    assert not missing, f"no test marked for: {sorted(missing)}"


def test_no_test_names_a_nonexistent_operation():
    assert _marked() <= set(operations)


def test_each_operation_has_more_than_a_happy_path():
    counts = {}
    for path in TESTS.glob("test_*.py"):
        if path.name != Path(__file__).name:
            for name in MARK.findall(path.read_text()):
                counts[name] = counts.get(name, 0) + 1
    # list_ai_product_options is one behavior (return the dropdown strings);
    # everything else needs at least two distinct tests.
    thin = sorted(
        name for name in operations if counts.get(name, 0) < 2 and name != "list_ai_product_options"
    )
    assert not thin, f"only one test for: {thin}"


LIVE_MARK = re.compile(r"live_op\(['\"]([a-z_]+)['\"]\)")


def test_every_operation_has_an_online_test():
    """The online suite proves each action against a real tenant (it skips
    without credentials)."""
    live = set(LIVE_MARK.findall((TESTS / "test_live.py").read_text()))
    missing = set(operations) - live
    assert not missing, f"no online test marked live_op for: {sorted(missing)}"
    assert live <= set(operations)
