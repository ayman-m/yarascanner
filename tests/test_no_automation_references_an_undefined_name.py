#!/usr/bin/env python3
"""No automation may reference a module-level name it does not define.

This exact bug has now been found three times in this pack, and every time it looked the same
from the outside: a function is copied from one automation into another, its module-level
dependency is not copied with it, and the result imports cleanly, passes every test that does
not happen to call it, and raises NameError the day somebody wires it up.

  1. `render_report` landed in four automations without `render_by_type`, which it calls.
  2. Fixing that inserted `report_datasets` into the CLI toolkit, which has neither
     `YARA_SCHEMA_VERSION` nor `classify_yara_datasets` nor `datetime`.
  3. `group_by_type` and `render_by_type` landed in four automations without `DATASET_TYPES`,
     `_TYPE_TITLES` or `_COUNT_ONLY_TYPES`.

Each was caught by a person reading carefully, twice by luck. That is not a control. The
property is mechanical, so assert it mechanically: for every function in every automation,
every name it loads must resolve to something the file defines, imports, binds locally, or
receives from the platform.

WHY THE SUITE DID NOT CATCH ANY OF THE THREE. These are all UNREACHABLE from the automation's
own `main()` - inlined-library code carried so the drift gates pass. Nothing calls them, so
nothing raises, so coverage says nothing. The gates themselves compare only the functions in
their own name list, and a constant that is missing entirely is not in anybody's list. This
test closes the gap the gates leave: they check that shared code has not DIVERGED, this checks
that shared code can actually RUN.
"""
import ast
import builtins
import io
import os

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts")

# Injected by CommonServerPython when the tenant loads the script. They are deliberately
# absent from the source - an automation that defined its own `demisto` would be the bug.
PLATFORM = {"demisto", "CommandResults", "return_results", "return_error",
            "argToList", "argToBoolean", "fileResult"}
_KNOWN = set(dir(builtins)) | PLATFORM


def _automations():
    return sorted(d for d in os.listdir(_SCRIPTS)
                  if os.path.isfile(os.path.join(_SCRIPTS, d, d + ".py")))


def _module_level(tree):
    """Everything bound at module scope: defs, classes, assignments, imports - including the
    imports inside a top-level try/except, which is how optional dependencies are brought in."""
    out = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                out.update(e.id for e in ast.walk(t) if isinstance(e, ast.Name))
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            out.update(e.id for e in ast.walk(node.target) if isinstance(e, ast.Name))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            out.update((a.asname or a.name).split(".")[0] for a in node.names)
        elif isinstance(node, (ast.Try, ast.If)):
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    out.update((a.asname or a.name).split(".")[0] for a in sub.names)
                elif isinstance(sub, ast.Assign):
                    for t in sub.targets:
                        out.update(e.id for e in ast.walk(t) if isinstance(e, ast.Name))
                elif isinstance(sub, ast.FunctionDef):
                    out.add(sub.name)
    return out


def _bound_inside(fn):
    """Every name bound anywhere inside `fn` - parameters, assignments, comprehension targets,
    loop and with targets, except-as names, nested defs, and imports made INSIDE the function.

    That last one matters: `_delete_many` does `import threading` in its body and `_as_ms` does
    `from datetime import timezone`, both deliberately lazy so a module missing on the tenant
    fails at the call rather than at load. A checker that ignored them would report two
    gate-protected functions as broken and be switched off for crying wolf.
    """
    out = {a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs}
    if fn.args.vararg:
        out.add(fn.args.vararg.arg)
    if fn.args.kwarg:
        out.add(fn.args.kwarg.arg)
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Assign):
            for t in sub.targets:
                out.update(e.id for e in ast.walk(t) if isinstance(e, ast.Name))
        elif isinstance(sub, (ast.AugAssign, ast.AnnAssign)):
            out.update(e.id for e in ast.walk(sub.target) if isinstance(e, ast.Name))
        elif isinstance(sub, (ast.Import, ast.ImportFrom)):
            out.update((a.asname or a.name).split(".")[0] for a in sub.names)
        elif isinstance(sub, ast.comprehension):
            out.update(e.id for e in ast.walk(sub.target) if isinstance(e, ast.Name))
        elif isinstance(sub, ast.ExceptHandler) and sub.name:
            out.add(sub.name)
        elif isinstance(sub, ast.For):
            out.update(e.id for e in ast.walk(sub.target) if isinstance(e, ast.Name))
        elif isinstance(sub, ast.withitem) and sub.optional_vars is not None:
            out.update(e.id for e in ast.walk(sub.optional_vars) if isinstance(e, ast.Name))
        elif isinstance(sub, ast.Lambda):
            out.update(a.arg for a in sub.args.args)
        elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub is not fn:
            out.add(sub.name)
            out.update(a.arg for a in sub.args.args)
        elif isinstance(sub, ast.Global):
            out.update(sub.names)
    return out


@pytest.mark.parametrize("automation", _automations())
def test_every_name_a_function_loads_actually_resolves(automation):
    path = os.path.join(_SCRIPTS, automation, automation + ".py")
    tree = ast.parse(io.open(path, encoding="utf-8").read())
    top = _KNOWN | _module_level(tree)

    # TOP-LEVEL functions only, deliberately. A nested function is checked as part of its
    # parent, because that is how Python resolves it: `worker` inside `_delete_many` reads
    # `lock`, `client` and `deleted` from the enclosing scope, and checking it standalone
    # reports every closure variable as undefined. _bound_inside already walks the whole
    # subtree, so an inner function's free variables are matched against the outer bindings.
    unresolved = {}
    for fn in [n for n in tree.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        local = _bound_inside(fn)
        for sub in ast.walk(fn):
            if (isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load)
                    and sub.id not in top and sub.id not in local):
                unresolved.setdefault(sub.id, set()).add(fn.name)

    assert not unresolved, (
        "%s references %d module-level name(s) it never defines - each is a NameError waiting "
        "for the first caller, and none of them is reachable from main() today, which is "
        "exactly why nothing else catches it:\n%s"
        % (automation, len(unresolved),
           "\n".join("    %-24s referenced by %s" % (n, ", ".join(sorted(f)))
                     for n, f in sorted(unresolved.items()))))


def test_the_shared_report_constants_are_wherever_their_functions_are():
    """The specific instance of the rule that has actually bitten, pinned by name so a failure
    says what to do. `group_by_type` and `render_by_type` are carried by every automation that
    carries `render_report` - which the drift gate requires - and all three read constants that
    the gate has no opinion about."""
    needs = {"group_by_type": ("DATASET_TYPES",),
             "render_by_type": ("_TYPE_TITLES", "_COUNT_ONLY_TYPES")}
    for automation in _automations():
        path = os.path.join(_SCRIPTS, automation, automation + ".py")
        tree = ast.parse(io.open(path, encoding="utf-8").read())
        defined = _module_level(tree)
        for fn, consts in needs.items():
            if fn not in defined:
                continue
            missing = [c for c in consts if c not in defined]
            assert not missing, (
                "%s carries %s but not %s, which it reads - copy the constants across too"
                % (automation, fn, missing))
