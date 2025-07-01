# encoding:utf-8
# Copyright (C) 2018 whitequark@whitequark.org
# 
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""
This module implements a C++ Itanium ABI demangler.

The demangler provides a single entry point, `demangle`, and returns either `None`
or an abstract syntax tree. All nodes have, at least, a `kind` field.

Name nodes:
    * `name`: `node.value` (`str`) holds an unqualified name
    * `ctor`: `node.value` is one of `"complete"`, `"base"`, or `"allocating"`, specifying
      the type of constructor
    * `dtor`: `node.value` is one of `"deleting"`, `"complete"`, or `"base"`, specifying
      the type of destructor
    * `oper`: `node.value` (`str`) holds a symbolic operator name, without the keyword
      "operator"
    * `oper_cast`: `node.value` holds a type node
    * `tpl_args`: `node.value` (`tuple`) holds a sequence of type nodes
    * `qual_name`: `node.value` (`tuple`) holds a sequence of `name` and `tpl_args` nodes,
      possibly ending in a `ctor`, `dtor` or `operator` node
    * `abi`: `node.value` holds a name node, `node.qual` (`frozenset`) holds a set of ABI tags

Type nodes:
    * `name` and `qual_name` specify a type by its name
    * `builtin`: `node.value` (`str`) specifies a builtin type by its name
    * `pointer`, `lvalue` and `rvalue`: `node.value` holds a pointee type node
    * `cv_qual`: `node.value` holds a type node, `node.qual` (`frozenset`) is any of
      `"const"`, `"volatile"`, or `"restrict"`
    * `literal`: `node.value` (`str`) holds the literal representation as-is,
      `node.ty` holds a type node specifying the type of the literal
    * `function`: `node.name` holds a name node specifying the function name,
      `node.ret_ty` holds a type node specifying the return type of a template function,
      if any, or `None`, ``node.arg_tys` (`tuple`) holds a sequence of type nodes
      specifying thefunction arguments

Special nodes:
    * `vtable`, `vtt`, `typeinfo`, and `typeinfo_name`: `node.value` holds a type node
      specifying the type described by this RTTI data structure
    * `nonvirt_thunk`, `virt_thunk`: `node.value` holds a function node specifying
      the function to which the thunk dispatches
"""

import re
from collections import namedtuple


class _Cursor:
    def __init__(self, raw, pos=0):
        self._raw = raw
        self._pos = pos
        self._substs = {}

    def at_end(self):
        return self._pos == len(self._raw)

    def accept(self, delim):
        if self._raw[self._pos:self._pos + len(delim)] == delim:
            self._pos += len(delim)
            return True

    def advance(self, amount):
        if self._pos + amount > len(self._raw):
            return None
        result = self._raw[self._pos:self._pos + amount]
        self._pos += amount
        return result

    def advance_until(self, delim):
        new_pos = self._raw.find(delim, self._pos)
        if new_pos == -1:
            return None
        result = self._raw[self._pos:new_pos]
        self._pos = new_pos + len(delim)
        return result

    def match(self, pattern):
        match = pattern.match(self._raw, self._pos)
        if match:
            self._pos = match.end(0)
        return match

    def add_subst(self, node):
        # print("S[{}] = {}".format(len(self._substs), str(node)))
        if not node in self._substs.values():
            self._substs[len(self._substs)] = node

    def resolve_subst(self, seq_id):
        if seq_id in self._substs:
            return self._substs[seq_id]

    def __repr__(self):
        return "_Cursor({}, {})".format(self._raw[:self._pos] + '→' + self._raw[self._pos:],
                                        self._pos)


class Node(namedtuple('Node', 'kind value')):
    def __repr__(self):
        return "<Node {} {}>".format(self.kind, repr(self.value))

    def __str__(self):
        if self.kind in ('name', 'builtin'):
            if self.value == '_GLOBAL__N_1':
                return '(anonymous namespace)'
            return self.value
        elif self.kind == 'qual_name':
            result = ''
            for node in self.value:
                if result != '' and node.kind != 'tpl_args':
                    result += '::'
                result += str(node)
            return result
        elif self.kind == 'tpl_args':
            result = '<' + ', '.join(map(str, self.value))
            if result.endswith('>'):
                result += ' '
            result += '>'
            return result
        elif self.kind == 'ctor':
            if self.value == 'complete':
                return '{ctor}'
            elif self.value == 'base':
                return '{base ctor}'
            elif self.value == 'allocating':
                return '{allocating ctor}'
            else:
                assert False
        elif self.kind == 'dtor':
            if self.value == 'deleting':
                return '{deleting dtor}'
            elif self.value == 'complete':
                return '{dtor}'
            elif self.value == 'base':
                return '{base dtor}'
            else:
                assert False
        elif self.kind == 'oper':
            if self.value.startswith('new') or self.value.startswith('delete'):
                return 'operator ' + self.value
            else:
                return 'operator' + self.value
        elif self.kind == 'oper_cast':
            return 'operator ' + str(self.value)
        elif self.kind == 'pointer':
            return str(self.value) + '*'
        elif self.kind == 'lvalue':
            return str(self.value) + '&'
        elif self.kind == 'rvalue':
            return str(self.value) + '&&'
        elif self.kind == 'tpl_param':
            return '{T' + str(self.value) + '}'
        elif self.kind == 'subst':
            return '{S' + str(self.value) + '}'
        elif self.kind == 'vtable':
            return 'vtable for ' + str(self.value)
        elif self.kind == 'vtt':
            return 'vtt for ' + str(self.value)
        elif self.kind == 'typeinfo':
            return 'typeinfo for ' + str(self.value)
        elif self.kind == 'typeinfo_name':
            return 'typeinfo name for ' + str(self.value)
        elif self.kind == 'nonvirt_thunk':
            return 'non-virtual thunk for ' + str(self.value)
        elif self.kind == 'virt_thunk':
            return 'virtual thunk for ' + str(self.value)
        else:
            return repr(self)

    def map(self, f):
        if self.kind in ('oper_cast', 'pointer', 'lvalue', 'rvalue', 'expand_arg_pack',
                         'vtable', 'vtt', 'typeinfo', 'typeinfo_name'):
            return self._replace(value=f(self.value))
        elif self.kind in ('qual_name', 'tpl_args', 'tpl_arg_pack'):
            return self._replace(value=tuple(map(f, self.value)))
        else:
            return self


class QualNode(namedtuple('QualNode', 'kind value qual')):
    def __repr__(self):
        return "<QualNode {} {} {}>".format(self.kind, repr(self.qual), repr(self.value))

    def __str__(self):
        if self.kind == 'abi':
            return str(self.value) + "".join(['[abi:' + tag + ']' for tag in self.qual])
        elif self.kind == 'cv_qual':
            return ' '.join([str(self.value)] + list(self.qual))
        else:
            return repr(self)

    def map(self, f):
        if self.kind == 'cv_qual':
            return self._replace(value=f(self.value))
        else:
            return self


class CastNode(namedtuple('CastNode', 'kind value ty')):
    def __repr__(self):
        return "<CastNode {} {} {}>".format(self.kind, repr(self.ty), repr(self.value))

    def __str__(self):
        if self.kind == 'literal':
            ty = str(self.ty)
            suffixes = {
                'long': 'l',
                'unsigned long': 'ul',
                'int': ''
            }
            value = str(self.value)
            if ty in suffixes:
                return value + suffixes[ty]
            if ty == 'bool' and value in ('0', '1'):
                return { '0': 'false', '1': 'true' }[value]
            return '(' + ty + ')' + value
        else:
            return repr(self)

    def map(self, f):
        if self.kind == 'literal':
            return self._replace(ty=f(self.ty))
        else:
            return self


class FuncNode(namedtuple('FuncNode', 'kind name arg_tys ret_ty')):
    def __repr__(self):
        return "<FuncNode {} {} {} {}>".format(self.kind, repr(self.name),
                                               repr(self.arg_tys), repr(self.ret_ty))

    def __str__(self):
        if self.kind == 'func':
            result = ""
            if self.ret_ty is not None:
                result += str(self.ret_ty) + ' '
            if self.name is not None:
                result += str(self.name)
            if self.arg_tys == (Node('builtin', 'void'),):
                result += '()'
            else:
                result += '(' + ', '.join(map(str, self.arg_tys)) + ')'
            return result
        else:
            return repr(self)

    def map(self, f):
        if self.kind == 'func':
            return self._replace(name=f(self.name) if self.name else None,
                                 arg_tys=tuple(map(f, self.arg_tys)),
                                 ret_ty=f(self.ret_ty) if self.ret_ty else None)
        else:
            return self


_ctor_dtor_map = {
    'C1': 'complete',
    'C2': 'base',
    'C3': 'allocating',
    'D0': 'deleting',
    'D1': 'complete',
    'D2': 'base'
}

_std_names = {
    'St': [Node('name', 'std')],
    'Sa': [Node('name', 'std'), Node('name', 'allocator')],
    'Sb': [Node('name', 'std'), Node('name', 'basic_string')],
    'Ss': [Node('name', 'std'), Node('name', 'string')],
    'Si': [Node('name', 'std'), Node('name', 'istream')],
    'So': [Node('name', 'std'), Node('name', 'ostream')],
    'Sd': [Node('name', 'std'), Node('name', 'iostream')],
}

_operators = {
    'nw': 'new',
    'na': 'new[]',
    'dl': 'delete',
    'da': 'delete[]',
    'ps': '+', # (unary)
    'ng': '-', # (unary)
    'ad': '&', # (unary)
    'de': '*', # (unary)
    'co': '~',
    'pl': '+',
    'mi': '-',
    'ml': '*',
    'dv': '/',
    'rm': '%',
    'an': '&',
    'or': '|',
    'eo': '^',
    'aS': '=',
    'pL': '+=',
    'mI': '-=',
    'mL': '*=',
    'dV': '/=',
    'rM': '%=',
    'aN': '&=',
    'oR': '|=',
    'eO': '^=',
    'ls': '<<',
    'rs': '>>',
    'lS': '<<=',
    'rS': '>>=',
    'eq': '==',
    'ne': '!=',
    'lt': '<',
    'gt': '>',
    'le': '<=',
    'ge': '>=',
    'nt': '!',
    'aa': '&&',
    'oo': '||',
    'pp': '++', # (postfix in <expression> context)
    'mm': '--', # (postfix in <expression> context)
    'cm': ',',
    'pm': '->*',
    'pt': '->',
    'cl': '()',
    'ix': '[]',
    'qu': '?',
}

_builtin_types = {
    'v':  'void',
    'w':  'wchar_t',
    'b':  'bool',
    'c':  'char',
    'a':  'signed char',
    'h':  'unsigned char',
    's':  'short',
    't':  'unsigned short',
    'i':  'int',
    'j':  'unsigned int',
    'l':  'long',
    'm':  'unsigned long',
    'x':  'long long',
    'y':  'unsigned long long',
    'n':  '__int128',
    'o':  'unsigned __int128',
    'f':  'float',
    'd':  'double',
    'e':  '__float80',
    'g':  '__float128',
    'z':  '...',
    'Di': 'char32_t',
    'Ds': 'char16_t',
    'Da': 'auto',
}


def _handle_cv(qualifiers, node):
    qualifier_set = set()
    if 'r' in qualifiers:
        qualifier_set.add('restrict')
    if 'V' in qualifiers:
        qualifier_set.add('volatile')
    if 'K' in qualifiers:
        qualifier_set.add('const')
    if qualifier_set:
        return QualNode('cv_qual', node, frozenset(qualifier_set))
    return node

def _handle_indirect(qualifier, node):
    if qualifier == 'P':
        return Node('pointer', node)
    elif qualifier == 'R':
        return Node('lvalue', node)
    elif qualifier == 'O':
        return Node('rvalue', node)
    return node


def _parse_seq_id(cursor):
    seq_id = cursor.advance_until('_')
    if seq_id is None:
        return None
    if seq_id == '':
        return 0
    else:
        return 1 + int(seq_id, 36)

def _parse_until_end(cursor, kind, fn):
    nodes = []
    while not cursor.accept('E'):
        node = fn(cursor)
        if node is None or cursor.at_end():
            return None
        nodes.append(node)
    return Node(kind, tuple(nodes))


_SOURCE_NAME_RE = re.compile(r"\d+")

def _parse_source_name(cursor):
    match = cursor.match(_SOURCE_NAME_RE)
    name_len = int(match.group(0))
    name = cursor.advance(name_len)
    if name is None:
        return None
    return name


_NAME_RE = re.compile(r"""
(?P<source_name>        (?= \d)) |
(?P<ctor_name>          C[123]) |
(?P<dtor_name>          D[012]) |
(?P<std_name>           S[absiod]) |
(?P<operator_name>      nw|na|dl|da|ps|ng|ad|de|co|pl|mi|ml|dv|rm|an|or|
                        eo|aS|pL|mI|mL|dV|rM|aN|oR|eO|ls|rs|lS|rS|eq|ne|
                        lt|gt|le|ge|nt|aa|oo|pp|mm|cm|pm|pt|cl|ix|qu) |
(?P<operator_cv>        cv) |
(?P<std_prefix>         St) |
(?P<substitution>       S) |
(?P<nested_name>        N (?P<cv_qual> [rVK]*) (?P<ref_qual> [RO]?)) |
(?P<template_param>     T) |
(?P<template_args>      I) |
(?P<constant>           L)
""", re.X)

def _parse_name(cursor, is_nested=False):
    match = cursor.match(_NAME_RE)
    if match is None:
        return None
    elif match.group('source_name') is not None:
        name = _parse_source_name(cursor)
        if name is None:
            return None
        node = Node('name', name)
    elif match.group('ctor_name') is not None:
        node = Node('ctor', _ctor_dtor_map[match.group('ctor_name')])
    elif match.group('dtor_name') is not None:
        node = Node('dtor', _ctor_dtor_map[match.group('dtor_name')])
    elif match.group('std_name') is not None:
        node = Node('qual_name', _std_names[match.group('std_name')])
    elif match.group('operator_name') is not None:
        node = Node('oper', _operators[match.group('operator_name')])
    elif match.group('operator_cv') is not None:
        ty = _parse_type(cursor)
        if ty is None:
            return None
        node = Node('oper_cast', ty)
    elif match.group('std_prefix') is not None:
        name = _parse_name(cursor, is_nested=True)
        if name is None:
            return None
        if name.kind == 'qual_name':
            node = Node('qual_name', (Node('name', 'std'),) + name.value)
        else:
            node = Node('qual_name', (Node('name', 'std'), name))
    elif match.group('substitution') is not None:
        seq_id = _parse_seq_id(cursor)
        if seq_id is None:
            return None
        node = cursor.resolve_subst(seq_id)
        if node is None:
            return None
    elif match.group('nested_name') is not None:
        nodes = []
        while True:
            name = _parse_name(cursor, is_nested=True)
            if name is None or cursor.at_end():
                return None
            if name.kind == 'qual_name':
                nodes += name.value
            else:
                nodes.append(name)
            if cursor.accept('E'):
                break
            else:
                cursor.add_subst(Node('qual_name', tuple(nodes)))
        node = Node('qual_name', tuple(nodes))
        node = _handle_cv(match.group('cv_qual'), node)
        node = _handle_indirect(match.group('ref_qual'), node)
    elif match.group('template_param') is not None:
        seq_id = _parse_seq_id(cursor)
        if seq_id is None:
            return None
        node = Node('tpl_param', seq_id)
        cursor.add_subst(node)
    elif match.group('template_args') is not None:
        node = _parse_until_end(cursor, 'tpl_args', _parse_type)
    elif match.group('constant') is not None:
        # not in the ABI doc, but probably means `const`
        return _parse_name(cursor, is_nested)
    if node is None:
        return None

    abi_tags = []
    while cursor.accept('B'):
        abi_tags.append(_parse_source_name(cursor))
    if abi_tags:
        node = QualNode('abi', node, frozenset(abi_tags))

    if not is_nested and cursor.accept('I') and (
            node.kind == 'name' or
            match.group('std_prefix') is not None or
            match.group('std_name') is not None or
            match.group('substitution') is not None):
        if node.kind == 'name' or match.group('std_prefix') is not None:
            cursor.add_subst(node) # <unscoped-template-name> ::= <substitution>
        templ_args = _parse_until_end(cursor, 'tpl_args', _parse_type)
        if templ_args is None:
            return None
        node = Node('qual_name', (node, templ_args))
        if (match.group('std_prefix') is not None or
                match.group('std_name') is not None):
            cursor.add_subst(node)

    return node


_TYPE_RE = re.compile(r"""
(?P<builtin_type>       v|w|b|c|a|h|s|t|i|j|l|m|x|y|n|o|f|d|e|g|z|
                        Dd|De|Df|Dh|DF|Di|Ds|Da|Dc|Dn) |
(?P<qualified_type>     [rVK]+) |
(?P<indirect_type>      [PRO]) |
(?P<function_type>      F) |
(?P<expression>         X) |
(?P<expr_primary>       (?= L)) |
(?P<template_arg_pack>  J) |
(?P<arg_pack_expansion> Dp) |
(?P<decltype>           D[tT])
""", re.X)

def _parse_type(cursor):
    match = cursor.match(_TYPE_RE)
    if match is None:
        node = _parse_name(cursor)
        cursor.add_subst(node)
    elif match.group('builtin_type') is not None:
        node = Node('builtin', _builtin_types[match.group('builtin_type')])
    elif match.group('qualified_type') is not None:
        ty = _parse_type(cursor)
        if ty is None:
            return None
        node = _handle_cv(match.group('qualified_type'), ty)
        cursor.add_subst(node)
    elif match.group('indirect_type') is not None:
        ty = _parse_type(cursor)
        if ty is None:
            return None
        node = _handle_indirect(match.group('indirect_type'), ty)
        cursor.add_subst(node)
    elif match.group('function_type') is not None:
        ret_ty = _parse_type(cursor)
        if ret_ty is None:
            return None
        arg_tys = []
        while not cursor.accept('E'):
            arg_ty = _parse_type(cursor)
            if arg_ty is None:
                return None
            arg_tys.append(arg_ty)
        node = FuncNode('func', None, tuple(arg_tys), ret_ty)
        cursor.add_subst(node)
    elif match.group('expression') is not None:
        raise NotImplementedError("expressions are not supported")
    elif match.group('expr_primary') is not None:
        node = _parse_expr_primary(cursor)
    elif match.group('template_arg_pack') is not None:
        node = _parse_until_end(cursor, 'tpl_arg_pack', _parse_type)
    elif match.group('arg_pack_expansion') is not None:
        node = _parse_type(cursor)
        node = Node('expand_arg_pack', node)
    elif match.group('decltype') is not None:
        raise NotImplementedError("decltype is not supported")
    else:
        return None
    return node


_EXPR_PRIMARY_RE = re.compile(r"""
(?P<mangled_name>       L (?= _Z)) |
(?P<literal>            L)
""", re.X)

def _parse_expr_primary(cursor):
    match = cursor.match(_EXPR_PRIMARY_RE)
    if match is None:
        return None
    elif match.group('mangled_name') is not None:
        mangled_name = cursor.advance_until('E')
        return _parse_mangled_name(_Cursor(mangled_name))
    elif match.group('literal') is not None:
        ty = _parse_type(cursor)
        if ty is None:
            return None
        value = cursor.advance_until('E')
        if value is None:
            return None
        return CastNode('literal', value, ty)


def _expand_template_args(func):
    if func.name.kind == 'qual_name':
        name_suffix = func.name.value[-1]
        if name_suffix.kind == 'tpl_args':
            tpl_args = name_suffix.value
            def mapper(node):
                if node.kind == 'tpl_param' and node.value < len(tpl_args):
                    return tpl_args[node.value]
                return node.map(mapper)
            return mapper(func)
    return func

def _parse_encoding(cursor):
    name = _parse_name(cursor)
    if name is None:
        return None
    if cursor.at_end():
        return name

    if name.kind == 'qual_name' and name.value[-1].kind == 'tpl_args':
        ret_ty = _parse_type(cursor)
        if ret_ty is None:
            return None
    else:
        ret_ty = None

    arg_tys = []
    while not cursor.at_end():
        arg_ty = _parse_type(cursor)
        if arg_ty is None:
            return None
        arg_tys.append(arg_ty)

    if arg_tys:
        func = FuncNode('func', name, tuple(arg_tys), ret_ty)
        return _expand_template_args(func)
    else:
        return name


_SPECIAL_RE = re.compile(r"""
(?P<rtti>               T (?P<kind> [VTIS])) |
(?P<nonvirtual_thunk>   Th (?P<nv_offset> n? \d+) _) |
(?P<virtual_thunk>      Tv (?P<v_offset> n? \d+) _ (?P<vcall_offset> n? \d+) _) |
(?P<covariant_thunk>    Tc)
""", re.X)

def _parse_special(cursor):
    match = cursor.match(_SPECIAL_RE)
    if match is None:
        return None
    elif match.group('rtti') is not None:
        name = _parse_type(cursor)
        if name is None:
            return None
        if match.group('kind') == 'V':
            return Node('vtable', name)
        elif match.group('kind') == 'T' is not None:
            return Node('vtt', name)
        elif match.group('kind') == 'I' is not None:
            return Node('typeinfo', name)
        elif match.group('kind') == 'S' is not None:
            return Node('typeinfo_name', name)
    elif match.group('nonvirtual_thunk') is not None:
        func = _parse_encoding(cursor)
        if func is None:
            return None
        return Node('nonvirt_thunk', func)
    elif match.group('virtual_thunk') is not None:
        func = _parse_encoding(cursor)
        if func is None:
            return None
        return Node('virt_thunk', func)
    elif match.group('covariant_thunk') is not None:
        raise NotImplementedError("covariant thunks are not supported")


_MANGLED_NAME_RE = re.compile(r"""
(?P<mangled_name>       _?_Z)
""", re.X)

def _parse_mangled_name(cursor):
    match = cursor.match(_MANGLED_NAME_RE)
    if match is None:
        return None
    else:
        special = _parse_special(cursor)
        if special is not None:
            return special

        return _parse_encoding(cursor)


def _expand_arg_packs(ast):
    def mapper(node):
        if node.kind == 'tpl_args':
            exp_args = []
            for arg in node.value:
                if arg.kind in ['tpl_arg_pack', 'tpl_args']:
                    exp_args += arg.value
                else:
                    exp_args.append(arg)
            return Node('tpl_args', tuple(map(mapper, exp_args)))
        elif node.kind == 'func':
            node = node.map(mapper)
            exp_arg_tys = []
            for arg_ty in node.arg_tys:
                if arg_ty.kind == 'expand_arg_pack' and \
                        arg_ty.value.kind == 'rvalue' and \
                            arg_ty.value.value.kind in ['tpl_arg_pack', 'tpl_args']:
                    exp_arg_tys += arg_ty.value.value.value
                else:
                    exp_arg_tys.append(arg_ty)
            return node._replace(arg_tys=tuple(exp_arg_tys))
        else:
            return node.map(mapper)
    return mapper(ast)

def parse(raw):
    ast = _parse_mangled_name(_Cursor(raw))
    if ast is not None:
        ast = _expand_arg_packs(ast)
    return ast

# ================================================================================================

import unittest


class TestDemangler(unittest.TestCase):
    def assertParses(self, mangled, ast):
        result = parse(mangled)
        self.assertEqual(result, ast)

    def assertDemangles(self, mangled, demangled):
        result = parse(mangled)
        if result is not None:
            result = str(result)
        self.assertEqual(result, demangled)

    def test_name(self):
        self.assertDemangles('_Z3foo', 'foo')
        self.assertDemangles('_Z3x', None)

    def test_ctor_dtor(self):
        self.assertDemangles('_ZN3fooC1E', 'foo::{ctor}')
        self.assertDemangles('_ZN3fooC2E', 'foo::{base ctor}')
        self.assertDemangles('_ZN3fooC3E', 'foo::{allocating ctor}')
        self.assertDemangles('_ZN3fooD0E', 'foo::{deleting dtor}')
        self.assertDemangles('_ZN3fooD1E', 'foo::{dtor}')
        self.assertDemangles('_ZN3fooD2E', 'foo::{base dtor}')

    def test_operator(self):
        for op in _operators:
            if _operators[op] in ['new', 'new[]', 'delete', 'delete[]']:
                continue
            self.assertDemangles('_Z' + op, 'operator' + _operators[op])
        self.assertDemangles('_Znw', 'operator new')
        self.assertDemangles('_Zna', 'operator new[]')
        self.assertDemangles('_Zdl', 'operator delete')
        self.assertDemangles('_Zda', 'operator delete[]')
        self.assertDemangles('_Zcvi', 'operator int')

    def test_std_substs(self):
        self.assertDemangles('_ZSt3foo', 'std::foo')
        self.assertDemangles('_ZStN3fooE', 'std::foo')
        self.assertDemangles('_ZSs', 'std::string')
        self.assertParses('_ZSt', None)
        self.assertDemangles('_Z3fooISt6vectorE', 'foo<std::vector>')
        self.assertDemangles('_ZSaIhE', 'std::allocator<unsigned char>')

    def test_nested_name(self):
        self.assertDemangles('_ZN3fooE', 'foo')
        self.assertDemangles('_ZN3foo5bargeE', 'foo::barge')
        self.assertDemangles('_ZN3fooIcE5bargeE', 'foo<char>::barge')
        self.assertDemangles('_ZNK3fooE', 'foo const')
        self.assertDemangles('_ZNV3fooE', 'foo volatile')
        self.assertDemangles('_ZNKR3fooE', 'foo const&')
        self.assertDemangles('_ZNKO3fooE', 'foo const&&')
        self.assertParses('_ZNKO3foo', None)

    def test_template_args(self):
        self.assertDemangles('_Z3fooIcE', 'foo<char>')
        self.assertDemangles('_ZN3fooIcEE', 'foo<char>')
        self.assertParses('_Z3fooI', None)

    def test_builtin_types(self):
        for ty in _builtin_types:
            self.assertDemangles('_Z1fI' + ty + 'E', 'f<' + _builtin_types[ty] + '>')

    def test_qualified_type(self):
        self.assertDemangles('_Z1fIriE', 'f<int restrict>')
        self.assertDemangles('_Z1fIKiE', 'f<int const>')
        self.assertDemangles('_Z1fIViE', 'f<int volatile>')
        self.assertDemangles('_Z1fIVVViE', 'f<int volatile>')

    def test_function_type(self):
        self.assertDemangles('_Z1fv', 'f()')
        self.assertDemangles('_Z1fi', 'f(int)')
        self.assertDemangles('_Z1fic', 'f(int, char)')
        self.assertDemangles('_ZN1fEic', 'f(int, char)')
        self.assertDemangles('_ZN1fIEEic', 'int f<>(char)')
        self.assertDemangles('_ZN1fIEC1Eic', 'f<>::{ctor}(int, char)')

    def test_indirect_type(self):
        self.assertDemangles('_Z1fIPiE', 'f<int*>')
        self.assertDemangles('_Z1fIRiE', 'f<int&>')
        self.assertDemangles('_Z1fIOiE', 'f<int&&>')
        self.assertDemangles('_Z1fIKRiE', 'f<int& const>')
        self.assertDemangles('_Z1fIRKiE', 'f<int const&>')

    def test_literal(self):
        self.assertDemangles('_Z1fILi1EE', 'f<(int)1>')
        self.assertDemangles('_Z1fIL_Z1gEE', 'f<g>')

    def test_argpack(self):
        self.assertDemangles('_Z1fILb0EJciEE', 'f<(bool)0, char, int>')
        self.assertDemangles('_Z1fILb0EIciEE', 'f<(bool)0, char, int>')
        self.assertDemangles('_Z1fIJciEEvDpOT_', 'void f<char, int>(char, int)')
        self.assertDemangles('_Z1fIIciEEvDpOT_', 'void f<char, int>(char, int)')

    def test_special(self):
        self.assertDemangles('_ZTV1f', 'vtable for f')
        self.assertDemangles('_ZTT1f', 'vtt for f')
        self.assertDemangles('_ZTI1f', 'typeinfo for f')
        self.assertDemangles('_ZTS1f', 'typeinfo name for f')
        self.assertDemangles('_ZThn16_1fv', 'non-virtual thunk for f()')
        self.assertDemangles('_ZTv16_8_1fv', 'virtual thunk for f()')

    def test_template_param(self):
        self.assertDemangles('_ZN1fIciEEvT_PT0_', 'void f<char, int>(char, int*)')
        self.assertParses('_ZN1fIciEEvT_PT0', None)

    def test_substitution(self):
        self.assertDemangles('_Z3fooIEvS_', 'void foo<>(foo)')
        self.assertDemangles('_ZN3foo3barIES_E', 'foo::bar<>::foo')
        self.assertDemangles('_ZN3foo3barIES0_E', 'foo::bar<>::foo::bar')
        self.assertDemangles('_ZN3foo3barIES1_E', 'foo::bar<>::foo::bar<>')
        self.assertParses('_ZN3foo3barIES_ES2_', None)
        self.assertDemangles('_Z3fooIS_E', 'foo<foo>')
        self.assertDemangles('_ZSt3fooIS_E', 'std::foo<std::foo>')
        self.assertDemangles('_Z3fooIPiEvS0_', 'void foo<int*>(int*)')
        self.assertDemangles('_Z3fooISaIcEEvS0_',
                             'void foo<std::allocator<char>>(std::allocator<char>)')
        self.assertDemangles('_Z3fooI3barS0_E', 'foo<bar, bar>')
        self.assertDemangles('_ZN2n11fEPNS_1bEPNS_2n21cEPNS2_2n31dE',
                             'n1::f(n1::b*, n1::n2::c*, n1::n2::n3::d*)')
        self.assertDemangles('_ZN1f1gES_IFvvEE', 'f::g(f<void ()>)')

    def test_abi_tag(self):
        self.assertDemangles('_Z3fooB5cxx11v', 'foo[abi:cxx11]()')

    def test_const(self):
        self.assertDemangles('_ZL3foo', 'foo')


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 1:
        while True:
            name = sys.stdin.readline()
            if not name:
                break
            print(parse(name.strip()))
    else:
        for name in sys.argv[1:]:
            ast = parse(name)
            print(repr(ast))
            print(ast)