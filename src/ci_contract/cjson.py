"""Strict ci-cjson-v1 parsing and serialization (not RFC 8785)."""
import json
from .errors import InputError

MAX_INTEGER = 9007199254740991


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
    """Return canonical UTF-8 bytes, preserving array order; reject non-JSON types."""
    active = set()

    def encode(item):
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
        active.add(identity)
        try:
            if type(item) is list:
                return '[' + ','.join(encode(v) for v in item) + ']'
            if any(type(k) is not str for k in item):
                raise InputError("non-string object key")
            return '{' + ','.join(_string(k) + ':' + encode(item[k]) for k in sorted(item)) + '}'
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
    """
    try:
        if type(data) is bytes:
            data = data.decode('utf-8', errors='strict')
        if type(data) is not str or data.startswith('\ufeff'):
            raise InputError("expected UTF-8 JSON without BOM")
        value = json.loads(data, object_pairs_hook=_pairs, parse_int=_integer,
                           parse_float=_reject, parse_constant=_reject)
        dumps(value)  # Validate scalar strings/keys, bounds, and nesting.
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise InputError("invalid JSON encoding or syntax") from None
