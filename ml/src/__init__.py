"""ML Package Root"""
from pathlib import Path

# Allow src namespace to find backend/src subpackages if present
backend_src_path = Path(__file__).resolve().parent.parent.parent / "backend" / "src"
if backend_src_path.exists() and str(backend_src_path) not in __path__:
    __path__.append(str(backend_src_path))
