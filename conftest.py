"""Make both editions importable after the per-edition reorganisation.

The scanners moved from the repo root into xdr/ and xsiam/, so `import xdr_yara_scanner`
no longer resolves from a test's own sys.path bootstrap. Rather than rewrite the import in
27 test files -- 21 of which import BOTH editions by name through their EDITIONS lists --
the two directories are put on sys.path here.

pytest imports a rootdir conftest.py before collecting anything, so this runs first.

Deliberately NOT a package: the scanners are delivered to endpoints as flat single-file
snippets, and making them package members would change how they import at the one place
that matters least (here) and most (there).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
for _sub in ("xdr", "xsiam", ""):
    _p = os.path.join(_ROOT, _sub) if _sub else _ROOT
    if _p not in sys.path:
        sys.path.insert(0, _p)
