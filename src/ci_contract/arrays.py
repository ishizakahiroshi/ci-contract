"""Exact, kind-specific canonical array registry; never infer by field name."""
import json
import re
from importlib.resources import files
from .cjson import dumps
from .errors import InputError


def load_registry():
    """Load and validate supported bundled registry rules, failing internally.

    Load during an operation, not import: bad bundled configuration must reach
    the CLI's existing internal-error handler (9), not escape as an import error.
    """
    registry = json.loads(files('ci_contract').joinpath('data/canonical-array-registry.json').read_bytes())
    if type(registry) is not dict or type(registry.get('entries')) is not list:
        raise RuntimeError("invalid bundled array registry")
    for entry in registry['entries']:
        if type(entry) is not dict or not {'classification', 'duplicates', 'sortKey'} <= entry.keys():
            raise RuntimeError("invalid bundled array registry")
        classification, duplicates, selectors = (entry[key] for key in
                                                 ('classification', 'duplicates', 'sortKey'))
        ordered = classification == 'ordered' and duplicates == 'allowed' and selectors is None
        exact = (classification == 'set' and duplicates == 'reject-exact-value'
                 and selectors == ['$value'])
        equal = (classification == 'set' and duplicates == 'reject-equal-sort-key'
                 and type(selectors) is list and bool(selectors)
                 and all(type(key) is str and (key in ('$value', '$canonicalBytes')
                         or re.fullmatch(r'(?:/(?:[^~]|~[01])*)+', key) is not None)
                         for key in selectors))
        if not (ordered or exact or equal):
            raise RuntimeError("unsupported bundled array registry rule")
    return registry


def _tokens(pointer):
    return tuple(p.replace('~1', '/').replace('~0', '~') for p in pointer.split('/')[1:])


def _sort_key(item, selectors):
    result = []
    for selector in selectors:
        if selector == '$canonicalBytes':
            result.append(dumps(item))
            continue
        value = item
        if selector != '$value':
            for token in _tokens(selector):
                if type(value) is not dict or token not in value:
                    raise InputError("missing set sort key")
                value = value[token]
        # Every scalar key in the pinned registry is a string in the schema.
        if type(value) is not str:
            raise InputError("set sort key must be a string")
        result.append(value)
    return tuple(result)


def normalize(value, document_kind=None):
    """Return a new value, normalize registered sets, reject their duplicates.

    Wildcards match only traversal through a list, never a numeric object key.
    Missing kind and unknown paths keep array order. Input is not mutated.
    """
    dumps(value)
    if document_kind is None and type(value) is dict:
        document_kind = value.get('kind')
    entries = [( _tokens(e['pointer']), e) for e in load_registry()['entries']
               if e['documentKind'] == document_kind]

    def visit(item, path):
        if type(item) is dict:
            return {k: visit(v, path + (k,)) for k, v in item.items()}
        if type(item) is not list:
            return item
        values = [visit(v, path + (i,)) for i, v in enumerate(item)]
        for pattern, entry in entries:
            if len(pattern) != len(path) or not all(
                    (a == '*' and type(b) is int) or (a != '*' and a == b)
                    for a, b in zip(pattern, path)):
                continue
            if entry['classification'] == 'ordered':
                return values
            keyed = [(_sort_key(v, entry['sortKey']), v) for v in values]
            keyed.sort(key=lambda pair: pair[0])
            if any(a[0] == b[0] for a, b in zip(keyed, keyed[1:])):
                raise InputError("duplicate set member")
            return [v for _, v in keyed]
        return values

    try:
        return visit(value, ())
    except RecursionError:
        raise InputError("JSON nesting too deep") from None
