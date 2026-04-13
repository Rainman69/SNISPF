#!/usr/bin/env python3
"""Direct entry point for running without installation."""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sni_spoofing.cli import main

if __name__ == "__main__":
    main()
