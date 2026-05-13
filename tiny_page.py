#!/usr/bin/env python3
"""TinyPage - Modern static page generator with cutting-edge WEB standards.

Entry point. Run with: python tiny_page.py
"""

import sys
from pathlib import Path

# Ensure tinypage package is importable
sys.path.insert(0, str(Path(__file__).parent))

from tinypage.server import main

if __name__ == "__main__":
    main()
