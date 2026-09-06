"""
Veritas Backend - Source Package Root
"""
from pathlib import Path

# Allow src namespace to find ml/src subpackages if present
ml_src_path = Path(__file__).resolve().parent.parent.parent / "ml" / "src"
if ml_src_path.exists() and str(ml_src_path) not in __path__:
    __path__.append(str(ml_src_path))
