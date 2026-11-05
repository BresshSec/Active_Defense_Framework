#!/usr/bin/env python3
"""Backward-compatible entry point for the PDF module."""

from athena.modules.pdf_defense import main

if __name__ == "__main__":
    raise SystemExit(main())

