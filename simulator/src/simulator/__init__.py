import sys
from pathlib import Path

# Add simulator root to path
SIM_DIR = Path(__file__).resolve().parent.parent.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))

from simulate import app, main
