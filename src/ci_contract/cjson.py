"""Strict ci-cjson-v1 parsing and serialization (not RFC 8785)."""
import json
import re
from itertools import accumulate
from .errors import InputError

MAX_INTEGER = 9007199254740991
# Maximum nesting of arrays and objects (the outermost container is level 1; a
# bare scalar is level 0). It is an explicit limit of this format, checked before
# any recursion, so the verdict never depends on the interpreter's recursion limit.
# The deepest document this package reads is its own bundled schema, 13 levels; the
# deepest contract document (a result with embedded proofs) is 7. 64 leaves a margin
# of about five times the schema and about nine times a contract document, while the
# serializer then uses at most about 130 interpreter frames, far below the default
# limit of 1000. Deeper input is invalid input (3).
MAX_DEPTH = 64
# Strings are removed whole (so brackets inside them are not counted), then every
# remaining non-bracket run; what is left is the bracket sequence of the text.
_STRINGS = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_NOT_BRACKETS = re.compile(r'[^\[\]{}]+')
_STEP = {'[': 1, '{': 1, ']': -1, '}': -1}


def _check_text_depth(text):
    """Refuse nesting over MAX_DEPTH in JSON text before the parser recurses."""
    brackets = _NOT_BRACKETS.sub('', _STRINGS.sub('', text))
    if max(accumulate(map(_STEP.__getitem__, brackets)), default=0) > MAX_DEPTH:
        raise InputError("JSON nesting too deep")


def _reject(_):
    raise InputError("unsupported numeric token")


def _integer(token):
    # Bound token length before int conversion, including huge untrusted input.
    if len(token.lstrip('-')) > 16:
        raise InputError("integer out of range")
    value = int(token)
    if abs(value) > MAX_INTEGER:
        raise InputError("integer out of range")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate object key")
        result[key] = value
    return result


def _string(value):
    parts = ['"']
    for ch in value:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise InputError("non-scalar Unicode")
        if ch == '"':
            parts.append('\\"')
        elif ch == '\\':
            parts.append('\\\\')
        elif cp < 0x20 or 0x7F <= cp <= 0x9F:
            parts.append(f'\\u{cp:04x}')
        else:
            parts.append(ch)
    parts.append('"')
    return ''.join(parts)


def dumps(value):
    """Return canonical UTF-8 bytes, preserving array order; reject non-JSON types.

    Nesting deeper than MAX_DEPTH is invalid input.
    """
    active = set()

    def encode(item, level=0):
        if item is None:
            return 'null'
        if type(item) is bool:
            return 'true' if item else 'false'
        if type(item) is int:
            if abs(item) > MAX_INTEGER:
                raise InputError("integer out of range")
            return str(item)
        if type(item) is str:
            return _string(item)
        if type(item) not in (list, dict):
            raise InputError("unsupported JSON value")
        identity = id(item)
        if identity in active:
            raise InputError("cyclic JSON value")
        if level >= MAX_DEPTH:  # Checked before descending, not by the interpreter.
            raise InputError("JSON nesting too deep")
        active.add(identity)
        try:
            if type(item) is list:
                return '[' + ','.join(encode(v, level + 1) for v in item) + ']'
            if any(type(k) is not str for k in item):
                raise InputError("non-string object key")
            return '{' + ','.join(_string(k) + ':' + encode(item[k], level + 1) for k in sorted(item)) + '}'
        finally:
            active.remove(identity)

    try:
        return encode(value).encode('utf-8')
    except RecursionError:
        raise InputError("JSON nesting too deep") from None


def loads(data):
    """Parse strict JSON; whitespace is accepted, -0 serializes as 0.

    Escaped surrogate pairs decode to a Unicode scalar; unpaired surrogates fail.
    No Unicode normalization or stripping of string values is performed.
    Nesting deeper than MAX_DEPTH is invalid input, decided before parsing.
    """
    try:
        if type(data) is bytes:
            data = data.decode('utf-8', errors='strict')
        if type(data) is not str or data.startswith('\ufeff'):
            raise InputError("expected UTF-8 JSON without BOM")
        _check_text_depth(data)  # Before the parser recurses (its own limit varies).
        value = json.loads(data, object_pairs_hook=_pairs, parse_int=_integer,
                           parse_float=_reject, parse_constant=_reject)
        dumps(value)  # Validate scalar strings/keys, bounds, and nesting.
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise InputError("invalid JSON encoding or syntax") from None
