import sys
from pathlib import Path

# Make `from app...` imports work when pytest runs from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
