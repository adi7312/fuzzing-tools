import os
import sys
from pathlib import Path


def pytest_configure():
    # Ensure headless matplotlib if present.
    os.environ.setdefault("MPLBACKEND", "Agg")


# Make repo root importable (so `import analysis...` works).
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
