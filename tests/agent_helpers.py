"""Makes the demo agent importable from tests (demo/ is not a package)."""

import sys

from conftest import DEMO

sys.path.insert(0, str(DEMO))

from agent import find_injected_order  # noqa: E402,F401
