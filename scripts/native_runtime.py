#!/usr/bin/env python3
"""Absolute-path friendly entry point for the isolated Linux native runner."""
from native_runner.main import serve

if __name__ == "__main__":
    raise SystemExit(serve())
