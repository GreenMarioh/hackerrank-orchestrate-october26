"""
conftest.py — pytest configuration for Ghost Data Still Exists.
Adds the repo root to sys.path so tests can import from code/.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
