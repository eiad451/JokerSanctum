import ast
import base64
import random
import string
import os


class _Renamer(ast.NodeTransformer):
    def __init__(self):
        self.map = {}
        self.c = 0
        self.skip = {
            'self', 'cls', 'True', 'False', 'None',
            '__init__', '__name__', '__main__', '__file__',
            '__class__', '__dict__', '__doc__', '__module__',
            '__builtins__', '__import__',
        }

    def _n(self):
        self.c += 1
        return f'_{self.c:04x}'

    def visit_FunctionDef(self, node):
        if node.name not in self.skip:
            self.map.setdefault(node.name, self._n())
            node.name = self.map[node.name]
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        if node.name not in self.skip:
            self.map.setdefault(node.name, self._n())
            node.name = self.map[node.name]
        self.generic_visit(node)
        return node

    def visit_Name(self, node):
        if node.id in self.map:
            node.id = self.map[node.id]
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        return node

    def visit_Arg(self, node):
        if node.arg not in self.skip:
            self.map.setdefault(node.arg, self._n())
            node.arg = self.map[node.arg]
        return node


class _StringEncoder(ast.NodeTransformer):
    def __init__(self):
        self.count = 0

    def _decode_call(self, s):
        enc = base64.b64encode(s.encode('utf-8') if isinstance(s, str) else s).decode()
        return ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    func=ast.Name(id='__import__', ctx=ast.Load()),
                    args=[ast.Constant(value='base64')],
                    keywords=[]
                ),
                attr='b64decode',
                ctx=ast.Load()
            ),
            args=[ast.Constant(value=enc)],
            keywords=[]
        )

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) > 3:
            dc = self._decode_call(node.value)
            dc = ast.Call(
                func=ast.Attribute(value=dc, attr='decode', ctx=ast.Load()),
                args=[],
                keywords=[]
            )
            return dc
        return node


def rename_identifiers(source: str) -> str:
    tree = ast.parse(source)
    _Renamer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def strip_comments_and_docstrings(source: str) -> str:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, (ast.Constant, ast.Str)):
                node.body.pop(0)
        if isinstance(node, ast.Module):
            while node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, (ast.Constant, ast.Str)):
                node.body.pop(0)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def encode_strings(source: str) -> str:
    try:
        tree = ast.parse(source)
        _StringEncoder().visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except Exception:
        return source


def inject_deadcode(source: str) -> str:
    lines = source.split('\n')
    insertions = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('def ') and stripped.endswith(':'):
            insertions.append(i + 1)
    dead_code = [
        '_ = lambda: None',
        'if 0: pass',
        '_x = 0xdeadbeef',
        '_ = [_ for _ in []]',
    ]
    offset = 0
    for idx in insertions:
        lines.insert(idx + offset, '    ' + random.choice(dead_code))
        offset += 1
    return '\n'.join(lines)


_FAKE_IMPORTS = [
    'import sys, json, csv, re, math',
    'from os import path, getcwd, listdir',
    'import warnings, traceback, logging',
    'from collections import defaultdict, Counter',
    'import itertools, functools, operator',
    'import xml.etree.ElementTree as ET',
    'from datetime import datetime, timedelta',
    'import decimal, fractions, statistics',
]

_ANTI_DEBUG = [
    'if __debug__: pass',
    'import sys as _sys; _sys_settrace = getattr(_sys, "settrace", lambda: None)',
    '_ = lambda: [x for x in (1,) if x]',
]


def inject_misleading_imports(source: str) -> str:
    imports = random.sample(_FAKE_IMPORTS, min(3, len(_FAKE_IMPORTS)))
    return '\n'.join(imports) + '\n' + source


def inject_anti_debug(source: str) -> str:
    lines = source.split('\n')
    idx = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('import ') or stripped.startswith('from '):
            idx = i + 1
    ad = random.choice(_ANTI_DEBUG)
    lines.insert(idx, ad)
    return '\n'.join(lines)


_PREFIX = 'Js'


def _uid():
    return _PREFIX + ''.join(random.choices(string.ascii_letters, k=6))


def obfuscate(
    source: str,
    rename: bool = True,
    strip_docs: bool = True,
    deadcode: bool = True,
    encode_strings_flag: bool = False,
    misleading_imports: bool = False,
    anti_debug: bool = False,
) -> str:
    result = source

    if misleading_imports:
        result = inject_misleading_imports(result)
    if strip_docs:
        result = strip_comments_and_docstrings(result)
    if encode_strings_flag:
        result = encode_strings(result)
    if rename:
        result = rename_identifiers(result)
    if deadcode:
        result = inject_deadcode(result)
    if anti_debug:
        result = inject_anti_debug(result)

    return result
