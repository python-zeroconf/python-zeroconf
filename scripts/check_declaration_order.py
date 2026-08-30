"""Enforce the repository's declaration ordering convention.

Methods within a class: dunders with ``__init__`` first, then public,
then private, each group alphabetical. Sibling classes at module level:
locally defined bases before their subclasses, alphabetical among
subclasses sharing the same locally defined bases. See CLAUDE.md for the rationale.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "zeroconf"


def method_sort_key(name: str) -> tuple[int, bool, str]:
    is_dunder = name.startswith("__") and name.endswith("__")
    is_private = not is_dunder and name.startswith("_")
    group = 0 if is_dunder else (2 if is_private else 1)
    return (group, name != "__init__", name)


def check_methods(rel: Path, cls: ast.ClassDef) -> list[str]:
    names = [node.name for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    # property setters share the getter's name; the sort is stable so
    # equal-name adjacency is always satisfiable
    expected = sorted(names, key=method_sort_key)
    if names != expected:
        return [
            f"{rel}:{cls.lineno}: class {cls.name}: method order breaks the "
            f"convention (dunders with __init__ first, then public, then "
            f"private, each alphabetical); expected: {', '.join(expected)}"
        ]
    return []


def check_class_order(rel: Path, tree: ast.Module) -> list[str]:
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    local = {cls.name for cls in classes}
    position = {cls.name: i for i, cls in enumerate(classes)}
    problems = []
    for i, cls in enumerate(classes):
        bases = sorted(b.id for b in cls.bases if isinstance(b, ast.Name) and b.id in local)
        for base in bases:
            if position[base] > i:
                problems.append(f"{rel}:{cls.lineno}: class {cls.name} is defined before its base {base}")
        if i:
            prev = classes[i - 1]
            prev_bases = sorted(b.id for b in prev.bases if isinstance(b, ast.Name) and b.id in local)
            if bases and prev_bases == bases and prev.name.lower() > cls.name.lower():
                problems.append(
                    f"{rel}:{cls.lineno}: class {cls.name} should come before its "
                    f"sibling {prev.name} (siblings with the same local bases are "
                    f"alphabetical)"
                )
    return problems


def check_file(path: Path) -> list[str]:
    rel = path.resolve().relative_to(ROOT)
    tree = ast.parse(path.read_text())
    problems = check_class_order(rel, tree)
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                problems.extend(check_methods(rel, child))
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.If)):
                stack.append(child)
    return problems


def main() -> int:
    paths = [Path(arg) for arg in sys.argv[1:]] or sorted(SRC.rglob("*.py"))
    problems: list[str] = []
    for path in paths:
        problems.extend(check_file(path))
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
