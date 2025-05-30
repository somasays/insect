"""Configure pytest for the project."""

import sys
from pathlib import Path

# Add project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
